package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.filter.ScimFilterParser;
import de.palsoftware.scim.server.impl.scim.mapper.ScimUserMapper;
import de.palsoftware.scim.server.impl.scim.patch.ScimPatchEngine;
import de.palsoftware.scim.server.impl.model.ScimGroupMembership;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.repository.ScimGroupMembershipRepository;
import de.palsoftware.scim.server.impl.repository.ScimUserRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.hibernate.Hibernate;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@Transactional(readOnly = true)
public class ScimUserService {

    private final ScimUserRepository userRepository;
    private final ScimGroupMembershipRepository membershipRepository;
    private final WorkspaceRepository workspaceRepository;
    private final WorkspaceActivityService workspaceActivityService;

    public ScimUserService(ScimUserRepository userRepository,
            ScimGroupMembershipRepository membershipRepository,
            WorkspaceRepository workspaceRepository,
            WorkspaceActivityService workspaceActivityService) {
        this.userRepository = userRepository;
        this.membershipRepository = membershipRepository;
        this.workspaceRepository = workspaceRepository;
        this.workspaceActivityService = workspaceActivityService;
    }

    @Transactional
    public ScimUser createUser(UUID workspaceId, Map<String, Object> input) {
        String userName = (String) input.get("userName");
        if (userName == null || userName.isBlank()) {
            throw new ScimException(400, "invalidValue", "userName is required");
        }

        if (userRepository.existsByUserNameIgnoreCaseAndWorkspaceId(userName, workspaceId)) {
            throw new ScimException(409, "uniqueness", "User with userName '" + userName + "' already exists");
        }

        Workspace ws = workspaceRepository.findById(workspaceId)
                .orElseThrow(() -> new ScimException(404, null, "Workspace not found"));

        ScimUser user = new ScimUser();
        user.setWorkspace(ws);
        ScimUserMapper.applyFromScimInput(user, input);

        ScimUser savedUser = userRepository.save(user);
        workspaceActivityService.touchWorkspace(workspaceId);
        initializeLazyCollections(savedUser);
        return savedUser;
    }

    public ScimUser getUser(UUID workspaceId, UUID userId) {
        ScimUser user = userRepository.findByIdAndWorkspaceId(userId, workspaceId)
                .orElseThrow(() -> new ScimException(404, null, "User not found: " + userId));
        initializeLazyCollections(user);
        return user;
    }

    public Map<String, Object> listUsers(UUID workspaceId, String filter, String sortBy,
            String sortOrder, int startIndex, int count) {
        Specification<ScimUser> spec = ScimFilterParser.parseUserFilter(filter, workspaceId);

        // Get total count
        long totalResults = userRepository.count(spec);

        if (count == 0) {
            return buildListResponse(Collections.emptyList(), totalResults, startIndex, 0);
        }

        // Sorting
        String sortAttr = ScimFilterParser.resolveUserSortAttribute(sortBy);
        Sort.Direction direction = "descending".equalsIgnoreCase(sortOrder)
                ? Sort.Direction.DESC
                : Sort.Direction.ASC;
        Sort sort = Sort.by(direction, sortAttr);

        // Pagination (SCIM is 1-based, Spring Data Pageable is 0-based)
        int offset = Math.max(0, startIndex - 1);
        int pageNumber = offset / count;
        int skipWithinPage = offset % count;

        Pageable pageable = PageRequest.of(pageNumber, count, sort);
        Page<ScimUser> resultPage = userRepository.findAll(spec, pageable);

        List<ScimUser> page;
        if (skipWithinPage > 0 && !resultPage.getContent().isEmpty()) {
            // SCIM startIndex may not align with page boundaries; fetch the needed slice
            page = resultPage.getContent().subList(
                    Math.min(skipWithinPage, resultPage.getContent().size()),
                    resultPage.getContent().size());
        } else {
            page = resultPage.getContent();
        }
        page.forEach(this::initializeLazyCollections);

        return buildListResponse(page, totalResults, startIndex, page.size());
    }

    private Map<String, Object> buildListResponse(List<ScimUser> users, long totalResults,
            int startIndex, int itemsPerPage) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:ListResponse"));
        response.put("totalResults", totalResults);
        response.put("startIndex", startIndex);
        response.put("itemsPerPage", itemsPerPage);
        // Resources will be populated by the controller with full SCIM representations
        response.put("Resources", users);
        return response;
    }

    @Transactional
    public ScimUser replaceUser(UUID workspaceId, UUID userId, Map<String, Object> input, String ifMatch) {
        ScimUser existing = getUser(workspaceId, userId);

        // Validate If-Match ETag for optimistic concurrency control
        if (ifMatch != null) {
            String currentETag = "W/\"" + existing.getVersion() + "\"";
            if (!ifMatch.equals(currentETag)) {
                throw new ScimException(412, null, "Failed to update. Resource changed on the server.");
            }
        }

        // Validate userName
        String newUserName = (String) input.get("userName");
        if (newUserName == null || newUserName.isBlank()) {
            throw new ScimException(400, "invalidValue", "userName is required");
        }

        // Check if id in body conflicts
        Object bodyId = input.get("id");
        if (bodyId != null && !userId.toString().equals(bodyId.toString())) {
            // Per RFC, either reject or ignore. We'll ignore the id mismatch for PUT.
        }

        // Check uniqueness if userName changed
        if (!existing.getUserName().equalsIgnoreCase(newUserName)
                && userRepository.existsByUserNameIgnoreCaseAndWorkspaceId(newUserName, workspaceId)) {
            throw new ScimException(409, "uniqueness", "User with userName '" + newUserName + "' already exists");
        }

        // PUT = full replacement
        ScimUserMapper.clearMutableAttributes(existing);
        ScimUserMapper.applyFromScimInput(existing, input);

        ScimUser savedUser = userRepository.save(existing);
        workspaceActivityService.touchWorkspace(workspaceId);
        initializeLazyCollections(savedUser);
        return savedUser;
    }

    @Transactional
    public ScimUser patchUser(UUID workspaceId, UUID userId, List<Map<String, Object>> operations, String ifMatch) {
        ScimUser user = getUser(workspaceId, userId);

        // Validate If-Match ETag for optimistic concurrency control
        if (ifMatch != null) {
            String currentETag = "W/\"" + user.getVersion() + "\"";
            if (!ifMatch.equals(currentETag)) {
                throw new ScimException(412, null, "Failed to update. Resource changed on the server.");
            }
        }

        ScimPatchEngine.applyPatchOperations(user, operations);
        ScimUser savedUser = userRepository.save(user);
        workspaceActivityService.touchWorkspace(workspaceId);
        initializeLazyCollections(savedUser);
        return savedUser;
    }

    @Transactional
    public void deleteUser(UUID workspaceId, UUID userId) {
        ScimUser user = getUser(workspaceId, userId);
        // Remove user from all groups
        membershipRepository.deleteByMemberValue(userId);
        userRepository.delete(user);
        workspaceActivityService.touchWorkspace(workspaceId);
    }

    /**
     * Get groups this user belongs to (for the read-only 'groups' attribute).
     */
    public List<Map<String, Object>> getUserGroups(UUID userId, String baseUrl) {
        List<ScimGroupMembership> memberships = membershipRepository.findByMemberValue(userId);
        return memberships.stream()
                .map(m -> {
                    Map<String, Object> g = new LinkedHashMap<>();
                    g.put("value", m.getGroup().getId().toString());
                    g.put("$ref", baseUrl + "/Groups/" + m.getGroup().getId());
                    g.put("display", m.getGroup().getDisplayName());
                    g.put("type", "direct");
                    return g;
                })
                .toList();
    }

    /**
     * Batch-load groups for multiple users in a single query (avoids N+1).
     */
    public Map<UUID, List<Map<String, Object>>> getUserGroupsBatch(List<UUID> userIds, String baseUrl) {
        if (userIds.isEmpty()) {
            return Collections.emptyMap();
        }
        List<ScimGroupMembership> memberships = membershipRepository.findByMemberValueIn(userIds);
        Map<UUID, List<Map<String, Object>>> result = new HashMap<>();
        for (ScimGroupMembership m : memberships) {
            Map<String, Object> g = new LinkedHashMap<>();
            g.put("value", m.getGroup().getId().toString());
            g.put("$ref", baseUrl + "/Groups/" + m.getGroup().getId());
            g.put("display", m.getGroup().getDisplayName());
            g.put("type", "direct");
            result.computeIfAbsent(m.getMemberValue(), k -> new ArrayList<>()).add(g);
        }
        return result;
    }

    private void initializeLazyCollections(ScimUser user) {
        if (user != null) {
            Hibernate.initialize(user.getEmails());
            Hibernate.initialize(user.getPhoneNumbers());
            Hibernate.initialize(user.getAddresses());
            Hibernate.initialize(user.getEntitlements());
            Hibernate.initialize(user.getRoles());
            Hibernate.initialize(user.getIms());
            Hibernate.initialize(user.getPhotos());
            Hibernate.initialize(user.getX509Certificates());
        }
    }
}
