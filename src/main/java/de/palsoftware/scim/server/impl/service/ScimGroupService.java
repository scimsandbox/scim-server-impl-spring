package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.filter.ScimFilterParser;
import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.model.ScimGroupMembership;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.repository.ScimGroupMembershipRepository;
import de.palsoftware.scim.server.impl.repository.ScimGroupRepository;
import de.palsoftware.scim.server.impl.repository.ScimUserRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.hibernate.Hibernate;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@Transactional(readOnly = true)
public class ScimGroupService {

    private static final String KEY_DISPLAY_NAME = "displayName";
    private static final String KEY_MEMBERS = "members";
    private static final String KEY_VALUE = "value";
    private static final String KEY_EXTERNAL_ID = "externalId";
    private static final String RESOURCE_TYPE_GROUP = "Group";
    private static final String RESOURCE_TYPE_USER = "User";
    private static final Pattern MEMBER_VALUE_FILTER = Pattern.compile(
            "value\\s+eq\\s+\"([^\"]+)\"",
            Pattern.CASE_INSENSITIVE);

    private final ScimGroupRepository groupRepository;
    private final ScimGroupMembershipRepository membershipRepository;
    private final ScimUserRepository userRepository;
    private final WorkspaceRepository workspaceRepository;
    private final WorkspaceActivityService workspaceActivityService;

    public ScimGroupService(ScimGroupRepository groupRepository,
            ScimGroupMembershipRepository membershipRepository,
            ScimUserRepository userRepository,
            WorkspaceRepository workspaceRepository,
            WorkspaceActivityService workspaceActivityService) {
        this.groupRepository = groupRepository;
        this.membershipRepository = membershipRepository;
        this.userRepository = userRepository;
        this.workspaceRepository = workspaceRepository;
        this.workspaceActivityService = workspaceActivityService;
    }

    @Transactional
    @SuppressWarnings("unchecked")
    public ScimGroup createGroup(UUID workspaceId, Map<String, Object> input) {
        String displayName = (String) input.get(KEY_DISPLAY_NAME);
        if (displayName == null || displayName.isBlank()) {
            throw new ScimException(400, "invalidValue", KEY_DISPLAY_NAME + " is required");
        }

        if (groupRepository.findByDisplayNameAndWorkspaceId(displayName, workspaceId).isPresent()) {
            throw new ScimException(409, "uniqueness",
                    RESOURCE_TYPE_GROUP + " with " + KEY_DISPLAY_NAME + " '" + displayName + "' already exists");
        }

        Workspace ws = workspaceRepository.findById(workspaceId)
                .orElseThrow(() -> new ScimException(404, null, "Workspace not found"));

        ScimGroup group = new ScimGroup();
        group.setWorkspace(ws);
        group.setDisplayName(displayName);

        Object externalId = input.get(KEY_EXTERNAL_ID);
        if (externalId != null) {
            group.setExternalId(externalId.toString());
        }

        group = groupRepository.save(group);

        // Add members
        List<Map<String, Object>> members = (List<Map<String, Object>>) input.get(KEY_MEMBERS);
        if (members != null) {
            for (Map<String, Object> m : members) {
                addMember(group, workspaceId, m);
            }
            group = groupRepository.save(group);
        }

        workspaceActivityService.touchWorkspace(workspaceId);
        Hibernate.initialize(group.getMembers());
        return group;
    }

    public ScimGroup getGroup(UUID workspaceId, UUID groupId) {
        ScimGroup group = groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)
                .orElseThrow(() -> new ScimException(404, null, "Group not found: " + groupId));
        Hibernate.initialize(group.getMembers());
        return group;
    }

    public Map<String, Object> listGroups(UUID workspaceId, String filter, String sortBy,
            String sortOrder, int startIndex, int count) {
        Specification<ScimGroup> spec = ScimFilterParser.parseGroupFilter(filter, workspaceId);

        long totalResults = groupRepository.count(spec);

        if (count == 0) {
            return buildListResponse(Collections.emptyList(), totalResults, startIndex, 0);
        }

        String sortAttr = ScimFilterParser.resolveGroupSortAttribute(sortBy);
        Sort.Direction direction = "descending".equalsIgnoreCase(sortOrder)
                ? Sort.Direction.DESC
                : Sort.Direction.ASC;
        Sort sort = Sort.by(direction, sortAttr);

        // Pagination (SCIM is 1-based, Spring Data Pageable is 0-based)
        int offset = Math.max(0, startIndex - 1);
        int pageNumber = offset / count;
        int skipWithinPage = offset % count;

        Pageable pageable = PageRequest.of(pageNumber, count, sort);
        Page<ScimGroup> resultPage = groupRepository.findAll(spec, pageable);

        List<ScimGroup> page;
        if (skipWithinPage > 0 && !resultPage.getContent().isEmpty()) {
            page = resultPage.getContent().subList(
                    Math.min(skipWithinPage, resultPage.getContent().size()),
                    resultPage.getContent().size());
        } else {
            page = resultPage.getContent();
        }
        page.forEach(g -> Hibernate.initialize(g.getMembers()));

        return buildListResponse(page, totalResults, startIndex, page.size());
    }

    private Map<String, Object> buildListResponse(List<ScimGroup> groups, long totalResults,
            int startIndex, int itemsPerPage) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:ListResponse"));
        response.put("totalResults", totalResults);
        response.put("startIndex", startIndex);
        response.put("itemsPerPage", itemsPerPage);
        response.put("Resources", groups);
        return response;
    }

    @Transactional
    @SuppressWarnings("unchecked")
    public ScimGroup replaceGroup(UUID workspaceId, UUID groupId, Map<String, Object> input, String ifMatch) {
        ScimGroup existing = getGroup(workspaceId, groupId);

        // Validate If-Match ETag for optimistic concurrency control
        if (ifMatch != null) {
            String currentETag = "W/\"" + existing.getVersion() + "\"";
            if (!ifMatch.equals(currentETag)) {
                throw new ScimException(412, null, "Failed to update. Resource changed on the server.");
            }
        }

        String displayName = (String) input.get(KEY_DISPLAY_NAME);
        if (displayName == null || displayName.isBlank()) {
            throw new ScimException(400, "invalidValue", KEY_DISPLAY_NAME + " is required");
        }

        // Check uniqueness if changed
        if (!existing.getDisplayName().equals(displayName)
                && groupRepository.findByDisplayNameAndWorkspaceId(displayName, workspaceId).isPresent()) {
            throw new ScimException(409, "uniqueness",
                    RESOURCE_TYPE_GROUP + " with " + KEY_DISPLAY_NAME + " '" + displayName + "' already exists");
        }

        existing.setDisplayName(displayName);
        Object externalId = input.get(KEY_EXTERNAL_ID);
        existing.setExternalId(externalId != null ? externalId.toString() : null);

        // Replace members entirely
        existing.getMembers().clear();
        groupRepository.saveAndFlush(existing);

        List<Map<String, Object>> members = (List<Map<String, Object>>) input.get(KEY_MEMBERS);
        if (members != null) {
            for (Map<String, Object> m : members) {
                addMember(existing, workspaceId, m);
            }
        }

        ScimGroup savedGroup = groupRepository.save(existing);
        workspaceActivityService.touchWorkspace(workspaceId);
        Hibernate.initialize(savedGroup.getMembers());
        return savedGroup;
    }

    @Transactional
    public ScimGroup patchGroup(UUID workspaceId, UUID groupId, List<Map<String, Object>> operations, String ifMatch) {
        ScimGroup group = getGroup(workspaceId, groupId);

        // Validate If-Match ETag for optimistic concurrency control
        if (ifMatch != null) {
            String currentETag = "W/\"" + group.getVersion() + "\"";
            if (!ifMatch.equals(currentETag)) {
                throw new ScimException(412, null, "Failed to update. Resource changed on the server.");
            }
        }

        for (Map<String, Object> op : operations) {
            applyPatchOperation(group, workspaceId, op);
        }

        ScimGroup savedGroup = groupRepository.save(group);
        workspaceActivityService.touchWorkspace(workspaceId);
        Hibernate.initialize(savedGroup.getMembers());
        return savedGroup;
    }

    private void applyPatchOperation(ScimGroup group, UUID workspaceId, Map<String, Object> op) {
        String opType = String.valueOf(op.get("op")).toLowerCase(Locale.ROOT);
        String path = (String) op.get("path");
        Object value = op.get(KEY_VALUE);

        switch (opType) {
            case "add" -> applyAddOperation(group, workspaceId, path, value);
            case "replace" -> applyReplaceOperation(group, workspaceId, path, value);
            case "remove" -> applyRemoveOperation(group, path, value);
            default -> throw new ScimException(400, "invalidValue", "Unsupported PATCH op: " + opType);
        }
    }

    private void applyAddOperation(ScimGroup group, UUID workspaceId, String path, Object value) {
        if (KEY_MEMBERS.equals(path) || path == null) {
            addMissingMembers(group, workspaceId, extractMembersPayload(value, true, "Invalid value for members add"));
            return;
        }
        if (KEY_DISPLAY_NAME.equals(path) && value instanceof String displayName) {
            group.setDisplayName(displayName);
        }
    }

    @SuppressWarnings("unchecked")
    private void applyReplaceOperation(ScimGroup group, UUID workspaceId, String path, Object value) {
        if (KEY_MEMBERS.equals(path)) {
            replaceMembers(group, workspaceId,
                    extractMembersPayload(value, false, "Invalid value for members replace"));
            return;
        }
        if (KEY_DISPLAY_NAME.equals(path) && value instanceof String displayName) {
            updateDisplayName(group, workspaceId, displayName);
            return;
        }
        if (KEY_EXTERNAL_ID.equals(path)) {
            group.setExternalId(value != null ? value.toString() : null);
            return;
        }
        if (path == null && value instanceof Map<?, ?> rawMap) {
            applyReplaceValueMap(group, workspaceId, (Map<String, Object>) rawMap);
        }
    }

    @SuppressWarnings("unchecked")
    private void applyRemoveOperation(ScimGroup group, String path, Object value) {
        if (KEY_MEMBERS.equals(path)) {
            group.getMembers().clear();
            return;
        }
        if (path != null && path.startsWith("members[")) {
            String filterExpr = path.substring(8, path.length() - 1);
            String targetValue = extractFilterValue(filterExpr);
            if (targetValue != null) {
                group.getMembers().removeIf(member -> memberValueEquals(member, targetValue));
            }
            return;
        }
        if (value instanceof List<?> rawList) {
            removeMembers(group, (List<Map<String, Object>>) rawList);
        }
    }

    private void applyReplaceValueMap(ScimGroup group, UUID workspaceId, Map<String, Object> valueMap) {
        if (valueMap.containsKey(KEY_DISPLAY_NAME)) {
            updateDisplayName(group, workspaceId, (String) valueMap.get(KEY_DISPLAY_NAME));
        }
        if (valueMap.containsKey(KEY_EXTERNAL_ID)) {
            Object externalId = valueMap.get(KEY_EXTERNAL_ID);
            group.setExternalId(externalId != null ? externalId.toString() : null);
        }
        if (valueMap.containsKey(KEY_MEMBERS)) {
            replaceMembers(group, workspaceId, castMembers(valueMap.get(KEY_MEMBERS)));
        }
    }

    private void updateDisplayName(ScimGroup group, UUID workspaceId, String newName) {
        if (!group.getDisplayName().equals(newName)
                && groupRepository.findByDisplayNameAndWorkspaceId(newName, workspaceId).isPresent()) {
            throw new ScimException(409, "uniqueness",
                    RESOURCE_TYPE_GROUP + " with " + KEY_DISPLAY_NAME + " '" + newName + "' already exists");
        }
        group.setDisplayName(newName);
    }

    private void addMissingMembers(ScimGroup group, UUID workspaceId, List<Map<String, Object>> membersToAdd) {
        for (Map<String, Object> member : membersToAdd) {
            String memberValue = toString(member.get(KEY_VALUE));
            if (memberValue == null
                    || group.getMembers().stream().anyMatch(existing -> memberValueEquals(existing, memberValue))) {
                continue;
            }
            addMember(group, workspaceId, member);
        }
    }

    private void replaceMembers(ScimGroup group, UUID workspaceId, List<Map<String, Object>> newMembers) {
        group.getMembers().clear();
        for (Map<String, Object> member : newMembers) {
            addMember(group, workspaceId, member);
        }
    }

    private void removeMembers(ScimGroup group, List<Map<String, Object>> membersToRemove) {
        for (Map<String, Object> member : membersToRemove) {
            String memberValue = toString(member.get(KEY_VALUE));
            if (memberValue != null) {
                group.getMembers().removeIf(existing -> memberValueEquals(existing, memberValue));
            }
        }
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> extractMembersPayload(Object value, boolean allowEnvelope, String errorMessage) {
        if (value instanceof List<?> rawList) {
            return (List<Map<String, Object>>) rawList;
        }
        if (value instanceof Map<?, ?> rawMap) {
            Map<String, Object> valueMap = (Map<String, Object>) rawMap;
            if (allowEnvelope && valueMap.containsKey(KEY_MEMBERS)) {
                return castMembers(valueMap.get(KEY_MEMBERS));
            }
            return List.of(valueMap);
        }
        throw new ScimException(400, "invalidValue", errorMessage);
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> castMembers(Object value) {
        if (value == null) {
            return List.of();
        }
        if (value instanceof List<?> rawList) {
            return (List<Map<String, Object>>) rawList;
        }
        throw new ScimException(400, "invalidValue", "Invalid members payload");
    }

    private boolean memberValueEquals(ScimGroupMembership membership, String memberValue) {
        return membership.getMemberValue().toString().equals(memberValue);
    }

    private String toString(Object value) {
        return value != null ? value.toString() : null;
    }

    @Transactional
    public void deleteGroup(UUID workspaceId, UUID groupId) {
        ScimGroup group = getGroup(workspaceId, groupId);
        membershipRepository.deleteByMemberValue(groupId);
        groupRepository.delete(group);
        workspaceActivityService.touchWorkspace(workspaceId);
    }

    private void addMember(ScimGroup group, UUID workspaceId, Map<String, Object> memberMap) {
        String memberValue = memberMap.get(KEY_VALUE) != null ? memberMap.get(KEY_VALUE).toString() : null;
        if (memberValue == null) {
            throw new ScimException(400, "invalidValue", "Member " + KEY_VALUE + " is required");
        }

        UUID memberId;
        try {
            memberId = UUID.fromString(memberValue);
        } catch (IllegalArgumentException e) {
            throw new ScimException(400, "invalidValue", "Invalid member value (must be UUID): " + memberValue, e);
        }

        // Determine member type
        String memberType = memberMap.get("type") != null ? memberMap.get("type").toString() : RESOURCE_TYPE_USER;
        if (!RESOURCE_TYPE_USER.equalsIgnoreCase(memberType) && !RESOURCE_TYPE_GROUP.equalsIgnoreCase(memberType)) {
            throw new ScimException(400, "invalidValue", "Invalid member type: " + memberType);
        }
        memberType = RESOURCE_TYPE_GROUP.equalsIgnoreCase(memberType) ? RESOURCE_TYPE_GROUP : RESOURCE_TYPE_USER;

        // Verify the member exists and resolve display name in one query
        ScimUser resolvedUser = null;
        if (RESOURCE_TYPE_USER.equalsIgnoreCase(memberType)) {
            resolvedUser = userRepository.findByIdAndWorkspaceId(memberId, workspaceId)
                    .orElseThrow(() -> new ScimException(404, "invalidValue",
                            RESOURCE_TYPE_USER + " not found: " + memberValue));
        }

        ScimGroupMembership membership = new ScimGroupMembership();
        membership.setGroup(group);
        membership.setMemberValue(memberId);
        membership.setMemberType(memberType);

        // Set display if provided, or derive from the resolved user
        if (memberMap.get("display") != null) {
            membership.setDisplay(memberMap.get("display").toString());
        } else if (resolvedUser != null) {
            membership.setDisplay(resolvedUser.getDisplayName() != null
                    ? resolvedUser.getDisplayName()
                    : resolvedUser.getUserName());
        }

        group.getMembers().add(membership);
    }

    private String extractFilterValue(String filterExpr) {
        Matcher matcher = MEMBER_VALUE_FILTER.matcher(filterExpr);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }
}
