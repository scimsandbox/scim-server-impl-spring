package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.model.*;
import de.palsoftware.scim.server.impl.repository.ScimGroupMembershipRepository;
import de.palsoftware.scim.server.impl.repository.ScimUserRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.filter.ScimFilterEvaluator;
import de.palsoftware.scim.server.impl.scim.filter.ScimFilterParser;
import de.palsoftware.scim.server.impl.scim.mapper.ScimUserMapper;
import de.palsoftware.scim.server.impl.scim.pagination.OffsetBasedPageRequest;
import de.palsoftware.scim.server.impl.scim.patch.ScimPatchEngine;
import de.palsoftware.scim.server.impl.scim.validation.ScimCanonicalizer;
import org.hibernate.Hibernate;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
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
        String userName = ScimCanonicalizer.requireNullableString(input.get("userName"), "userName");
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
        resolveEnterpriseManagerDisplay(workspaceId, user);

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
        if (ScimFilterParser.containsValuePath(filter)) {
            ScimFilterParser.FilterNode ast = ScimFilterParser.parseAst(filter, true);
            String sortAttr = ScimFilterParser.resolveUserSortAttribute(sortBy);
            boolean isDescending = "descending".equalsIgnoreCase(sortOrder);

            Specification<ScimUser> wsSpec = ScimFilterParser.parseUserFilter(null, workspaceId);
            List<ScimUser> candidates = userRepository.findAll(wsSpec);
            if (candidates == null) {
                candidates = Collections.emptyList();
            }
            Map<UUID, List<Map<String, Object>>> groupsMap = Collections.emptyMap();
            if (!candidates.isEmpty() && ScimFilterParser.astReferencesGroups(ast)) {
                List<UUID> ids = candidates.stream().map(ScimUser::getId).filter(Objects::nonNull).toList();
                groupsMap = getUserGroupsBatch(ids, "");
            }

            List<ScimUser> matched = new ArrayList<>();
            for (ScimUser u : candidates) {
                initializeLazyCollections(u);
                List<Map<String, Object>> uGroups = groupsMap.getOrDefault(u.getId(), Collections.emptyList());
                if (ScimFilterEvaluator.matchesUser(u, uGroups, ast)) {
                    matched.add(u);
                }
            }

            long totalResults = matched.size();
            if (count == 0) {
                return buildListResponse(Collections.emptyList(), totalResults, startIndex, 0);
            }

            matched.sort(buildUserInMemoryComparator(sortAttr, isDescending));
            int offset = Math.max(0, startIndex - 1);
            List<ScimUser> page = offset >= matched.size()
                    ? Collections.emptyList()
                    : matched.subList(offset, Math.min(offset + count, matched.size()));
            return buildListResponse(page, totalResults, startIndex, page.size());
        }

        Specification<ScimUser> spec = ScimFilterParser.parseUserFilter(filter, workspaceId);

        // Get total count
        long totalResults = userRepository.count(spec);

        if (count == 0) {
            return buildListResponse(Collections.emptyList(), totalResults, startIndex, 0);
        }

        // Sorting
        String sortAttr = ScimFilterParser.resolveUserSortAttribute(sortBy);
        boolean isDescending = "descending".equalsIgnoreCase(sortOrder);

        if ("emails".equals(sortAttr)) {
            List<ScimUser> allUsers = new ArrayList<>(userRepository.findAll(spec));
            Comparator<ScimUser> userComparator = buildUserInMemoryComparator(sortAttr, isDescending);
            allUsers.sort(userComparator);

            int offset = Math.max(0, startIndex - 1);
            List<ScimUser> page;
            if (offset >= allUsers.size()) {
                page = Collections.emptyList();
            } else {
                page = allUsers.subList(offset, Math.min(offset + count, allUsers.size()));
            }
            page.forEach(this::initializeLazyCollections);

            return buildListResponse(page, totalResults, startIndex, page.size());
        }

        Sort.Order primaryOrder = isDescending
                ? Sort.Order.desc(sortAttr).nullsFirst()
                : Sort.Order.asc(sortAttr).nullsLast();
        if (!isSortAttributeCaseExact(sortAttr)) {
            primaryOrder = primaryOrder.ignoreCase();
        }
        Sort.Order tieBreaker = isDescending ? Sort.Order.desc("id") : Sort.Order.asc("id");
        Sort sort = "id".equals(sortAttr) ? Sort.by(primaryOrder) : Sort.by(primaryOrder, tieBreaker);

        int offset = Math.max(0, startIndex - 1);
        Pageable pageable = new OffsetBasedPageRequest(offset, count, sort);
        Page<ScimUser> resultPage = userRepository.findAll(spec, pageable);

        List<ScimUser> page = resultPage.getContent();
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

        validateIfMatch(ifMatch, existing.getVersion());

        // Validate userName
        String newUserName = ScimCanonicalizer.requireNullableString(input.get("userName"), "userName");
        if (newUserName == null || newUserName.isBlank()) {
            throw new ScimException(400, "invalidValue", "userName is required");
        }

        // Check uniqueness if userName changed
        if (!existing.getUserName().equalsIgnoreCase(newUserName)
                && userRepository.existsByUserNameIgnoreCaseAndWorkspaceId(newUserName, workspaceId)) {
            throw new ScimException(409, "uniqueness", "User with userName '" + newUserName + "' already exists");
        }

        // PUT = full replacement (validate on a draft copy so invalid payloads never mutate existing state)
        ScimUser draft = copyUser(existing);
        ScimUserMapper.clearMutableAttributes(draft);
        ScimUserMapper.applyFromScimInput(draft, input);
        resolveEnterpriseManagerDisplay(workspaceId, draft);

        copyMutableState(draft, existing);
        ScimUser savedUser = userRepository.save(existing);
        workspaceActivityService.touchWorkspace(workspaceId);
        initializeLazyCollections(savedUser);
        return savedUser;
    }

    @Transactional
    public ScimUser patchUser(UUID workspaceId, UUID userId, List<Map<String, Object>> operations, String ifMatch) {
        ScimUser user = getUser(workspaceId, userId);
        String originalUserName = user.getUserName();

        validateIfMatch(ifMatch, user.getVersion());

        ScimUser draft = copyUser(user);
        ScimPatchEngine.applyPatchOperations(draft, operations);
        draft.setUserName(ScimCanonicalizer.normalizeNfc(draft.getUserName()));

        if (draft.getUserName() == null || draft.getUserName().isBlank()) {
            throw new ScimException(400, "invalidValue", "userName is required");
        }

        if (!draft.getUserName().equalsIgnoreCase(originalUserName)
                && userRepository.existsByUserNameIgnoreCaseAndWorkspaceId(draft.getUserName(), workspaceId)) {
            throw new ScimException(409, "uniqueness", "User with userName '" + draft.getUserName() + "' already exists");
        }

        if (draft.getEnterpriseManagerValue() == null || draft.getEnterpriseManagerValue().isBlank()) {
            draft.setEnterpriseManagerDisplay(null);
        } else if (!Objects.equals(user.getEnterpriseManagerValue(), draft.getEnterpriseManagerValue())
                || draft.getEnterpriseManagerDisplay() == null) {
            resolveEnterpriseManagerDisplay(workspaceId, draft);
        }

        if (!hasUserChanged(user, draft)) {
            return user;
        }

        copyMutableState(draft, user);
        ScimUser savedUser = userRepository.save(user);
        workspaceActivityService.touchWorkspace(workspaceId);
        initializeLazyCollections(savedUser);
        return savedUser;
    }

    @Transactional
    public void deleteUser(UUID workspaceId, UUID userId) {
        deleteUser(workspaceId, userId, null);
    }

    @Transactional
    public void deleteUser(UUID workspaceId, UUID userId, String ifMatch) {
        ScimUser user = getUser(workspaceId, userId);
        validateIfMatch(ifMatch, user.getVersion());
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

    private void resolveEnterpriseManagerDisplay(UUID workspaceId, ScimUser target) {
        String mgrVal = target.getEnterpriseManagerValue();
        if (mgrVal == null || mgrVal.isBlank()) {
            target.setEnterpriseManagerDisplay(null);
            return;
        }
        try {
            UUID mgrId = UUID.fromString(mgrVal.trim());
            Optional<ScimUser> mgrOpt = userRepository.findByIdAndWorkspaceId(mgrId, workspaceId);
            if (mgrOpt != null && mgrOpt.isPresent()) {
                ScimUser mgr = mgrOpt.get();
                target.setEnterpriseManagerDisplay(
                        mgr.getDisplayName() != null ? mgr.getDisplayName() : mgr.getUserName());
            } else {
                target.setEnterpriseManagerDisplay(null);
            }
        } catch (IllegalArgumentException ignored) {
            target.setEnterpriseManagerDisplay(null);
        }
    }

    public Comparator<ScimUser> buildUserInMemoryComparator(String sortAttr, boolean isDescending) {
        Comparator<ScimUser> primary;
        if ("createdAt".equals(sortAttr) || "lastModified".equals(sortAttr)) {
            Comparator<java.time.Instant> cmp = Comparator.naturalOrder();
            primary = isDescending
                    ? Comparator.comparing(u -> "createdAt".equals(sortAttr) ? u.getCreatedAt() : u.getLastModified(),
                            Comparator.nullsFirst(cmp.reversed()))
                    : Comparator.comparing(u -> "createdAt".equals(sortAttr) ? u.getCreatedAt() : u.getLastModified(),
                            Comparator.nullsLast(cmp));
        } else if ("active".equals(sortAttr)) {
            Comparator<Boolean> cmp = Comparator.naturalOrder();
            primary = isDescending
                    ? Comparator.comparing(ScimUser::isActive, cmp.reversed())
                    : Comparator.comparing(ScimUser::isActive, cmp);
        } else {
            Comparator<String> strCmp = isSortAttributeCaseExact(sortAttr)
                    ? Comparator.naturalOrder()
                    : String.CASE_INSENSITIVE_ORDER;
            primary = isDescending
                    ? Comparator.comparing(u -> extractUserSortString(u, sortAttr), Comparator.nullsFirst(strCmp.reversed()))
                    : Comparator.comparing(u -> extractUserSortString(u, sortAttr), Comparator.nullsLast(strCmp));
        }
        Comparator<String> idCmp = isDescending ? Comparator.reverseOrder() : Comparator.naturalOrder();
        return primary.thenComparing(u -> u.getId() != null ? u.getId().toString() : "", idCmp);
    }

    private String extractUserSortString(ScimUser u, String sortAttr) {
        return switch (sortAttr) {
            case "id" -> u.getId() != null ? u.getId().toString() : null;
            case "userName" -> u.getUserName();
            case "externalId" -> u.getExternalId();
            case "displayName" -> u.getDisplayName();
            case "nickName" -> u.getNickName();
            case "profileUrl" -> u.getProfileUrl();
            case "title" -> u.getTitle();
            case "userType" -> u.getUserType();
            case "preferredLanguage" -> u.getPreferredLanguage();
            case "locale" -> u.getLocale();
            case "timezone" -> u.getTimezone();
            case "nameFormatted" -> u.getNameFormatted();
            case "nameFamilyName" -> u.getNameFamilyName();
            case "nameGivenName" -> u.getNameGivenName();
            case "nameMiddleName" -> u.getNameMiddleName();
            case "nameHonorificPrefix" -> u.getNameHonorificPrefix();
            case "nameHonorificSuffix" -> u.getNameHonorificSuffix();
            case "enterpriseEmployeeNumber" -> u.getEnterpriseEmployeeNumber();
            case "enterpriseCostCenter" -> u.getEnterpriseCostCenter();
            case "enterpriseOrganization" -> u.getEnterpriseOrganization();
            case "enterpriseDivision" -> u.getEnterpriseDivision();
            case "enterpriseDepartment" -> u.getEnterpriseDepartment();
            case "emails" -> extractPrimaryOrFirstEmail(u);
            default -> u.getUserName();
        };
    }

    private static boolean isSortAttributeCaseExact(String sortAttr) {
        return switch (sortAttr) {
            case "id", "externalId", "profileUrl", "createdAt", "lastModified", "active" -> true;
            default -> false;
        };
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

    private String extractPrimaryOrFirstEmail(ScimUser u) {
        if (u == null || u.getEmails() == null || u.getEmails().isEmpty()) {
            return null;
        }
        for (ScimUserEmail e : u.getEmails()) {
            if (e != null && e.isPrimaryFlag() && e.getValue() != null && !e.getValue().isBlank()) {
                return e.getValue();
            }
        }
        for (ScimUserEmail e : u.getEmails()) {
            if (e != null && e.getValue() != null && !e.getValue().isBlank()) {
                return e.getValue();
            }
        }
        return null;
    }

    private void validateIfMatch(String ifMatch, Long version) {
        if (ifMatch != null && !isWildcardETag(ifMatch)) {
            String currentETag = "W/\"" + (version != null ? version : 0L) + "\"";
            if (!ifMatch.trim().equals(currentETag)) {
                throw new ScimException(412, null, "Failed to update. Resource changed on the server.");
            }
        }
    }

    private boolean isWildcardETag(String etag) {
        String trimmed = etag.trim();
        return "*".equals(trimmed) || "\"*\"".equals(trimmed);
    }

    private static ScimUser copyUser(ScimUser src) {
        ScimUser copy = new ScimUser();
        copy.setId(src.getId());
        copy.setWorkspace(src.getWorkspace());
        copy.setCreatedAt(src.getCreatedAt());
        copy.setLastModified(src.getLastModified());
        copy.setVersion(src.getVersion());
        copyMutableState(src, copy);
        return copy;
    }

    private static void copyMutableState(ScimUser src, ScimUser dst) {
        dst.setUserName(src.getUserName());
        dst.setExternalId(src.getExternalId());
        dst.setNameFormatted(src.getNameFormatted());
        dst.setNameFamilyName(src.getNameFamilyName());
        dst.setNameGivenName(src.getNameGivenName());
        dst.setNameMiddleName(src.getNameMiddleName());
        dst.setNameHonorificPrefix(src.getNameHonorificPrefix());
        dst.setNameHonorificSuffix(src.getNameHonorificSuffix());
        dst.setDisplayName(src.getDisplayName());
        dst.setNickName(src.getNickName());
        dst.setProfileUrl(src.getProfileUrl());
        dst.setTitle(src.getTitle());
        dst.setUserType(src.getUserType());
        dst.setPreferredLanguage(src.getPreferredLanguage());
        dst.setLocale(src.getLocale());
        dst.setTimezone(src.getTimezone());
        dst.setActive(src.isActive());
        dst.setPassword(src.getPassword());
        dst.setEnterpriseEmployeeNumber(src.getEnterpriseEmployeeNumber());
        dst.setEnterpriseCostCenter(src.getEnterpriseCostCenter());
        dst.setEnterpriseOrganization(src.getEnterpriseOrganization());
        dst.setEnterpriseDivision(src.getEnterpriseDivision());
        dst.setEnterpriseDepartment(src.getEnterpriseDepartment());
        dst.setEnterpriseManagerValue(src.getEnterpriseManagerValue());
        dst.setEnterpriseManagerRef(src.getEnterpriseManagerRef());
        dst.setEnterpriseManagerDisplay(src.getEnterpriseManagerDisplay());

        List<ScimUserEmail> emails = new ArrayList<>();
        if (src.getEmails() != null) {
            for (ScimUserEmail e : src.getEmails()) {
                ScimUserEmail c = new ScimUserEmail();
                c.setValue(e.getValue());
                c.setType(e.getType());
                c.setDisplay(e.getDisplay());
                c.setPrimaryFlag(e.isPrimaryFlag());
                emails.add(c);
            }
        }
        dst.setEmails(emails);

        List<ScimUserPhoneNumber> phones = new ArrayList<>();
        if (src.getPhoneNumbers() != null) {
            for (ScimUserPhoneNumber p : src.getPhoneNumbers()) {
                ScimUserPhoneNumber c = new ScimUserPhoneNumber();
                c.setValue(p.getValue());
                c.setType(p.getType());
                c.setDisplay(p.getDisplay());
                c.setPrimaryFlag(p.isPrimaryFlag());
                phones.add(c);
            }
        }
        dst.setPhoneNumbers(phones);

        List<ScimUserAddress> addrs = new ArrayList<>();
        if (src.getAddresses() != null) {
            for (ScimUserAddress a : src.getAddresses()) {
                ScimUserAddress c = new ScimUserAddress();
                c.setFormatted(a.getFormatted());
                c.setStreetAddress(a.getStreetAddress());
                c.setLocality(a.getLocality());
                c.setRegion(a.getRegion());
                c.setPostalCode(a.getPostalCode());
                c.setCountry(a.getCountry());
                c.setType(a.getType());
                c.setPrimaryFlag(a.isPrimaryFlag());
                addrs.add(c);
            }
        }
        dst.setAddresses(addrs);

        List<ScimUserEntitlement> ents = new ArrayList<>();
        if (src.getEntitlements() != null) {
            for (ScimUserEntitlement e : src.getEntitlements()) {
                ScimUserEntitlement c = new ScimUserEntitlement();
                c.setValue(e.getValue());
                c.setType(e.getType());
                c.setDisplay(e.getDisplay());
                c.setPrimaryFlag(e.isPrimaryFlag());
                ents.add(c);
            }
        }
        dst.setEntitlements(ents);

        List<ScimUserRole> roles = new ArrayList<>();
        if (src.getRoles() != null) {
            for (ScimUserRole r : src.getRoles()) {
                ScimUserRole c = new ScimUserRole();
                c.setValue(r.getValue());
                c.setType(r.getType());
                c.setDisplay(r.getDisplay());
                c.setPrimaryFlag(r.isPrimaryFlag());
                roles.add(c);
            }
        }
        dst.setRoles(roles);

        List<ScimUserIm> ims = new ArrayList<>();
        if (src.getIms() != null) {
            for (ScimUserIm im : src.getIms()) {
                ScimUserIm c = new ScimUserIm();
                c.setValue(im.getValue());
                c.setType(im.getType());
                c.setDisplay(im.getDisplay());
                c.setPrimaryFlag(im.isPrimaryFlag());
                ims.add(c);
            }
        }
        dst.setIms(ims);

        List<ScimUserPhoto> photos = new ArrayList<>();
        if (src.getPhotos() != null) {
            for (ScimUserPhoto ph : src.getPhotos()) {
                ScimUserPhoto c = new ScimUserPhoto();
                c.setValue(ph.getValue());
                c.setType(ph.getType());
                c.setDisplay(ph.getDisplay());
                c.setPrimaryFlag(ph.isPrimaryFlag());
                photos.add(c);
            }
        }
        dst.setPhotos(photos);

        List<ScimUserX509Certificate> certs = new ArrayList<>();
        if (src.getX509Certificates() != null) {
            for (ScimUserX509Certificate cert : src.getX509Certificates()) {
                ScimUserX509Certificate c = new ScimUserX509Certificate();
                c.setValue(cert.getValue());
                c.setType(cert.getType());
                c.setDisplay(cert.getDisplay());
                c.setPrimaryFlag(cert.isPrimaryFlag());
                certs.add(c);
            }
        }
        dst.setX509Certificates(certs);
    }

    private static boolean hasUserChanged(ScimUser a, ScimUser b) {
        return !Objects.equals(a.getUserName(), b.getUserName())
                || !Objects.equals(a.getExternalId(), b.getExternalId())
                || !Objects.equals(a.getNameFormatted(), b.getNameFormatted())
                || !Objects.equals(a.getNameFamilyName(), b.getNameFamilyName())
                || !Objects.equals(a.getNameGivenName(), b.getNameGivenName())
                || !Objects.equals(a.getNameMiddleName(), b.getNameMiddleName())
                || !Objects.equals(a.getNameHonorificPrefix(), b.getNameHonorificPrefix())
                || !Objects.equals(a.getNameHonorificSuffix(), b.getNameHonorificSuffix())
                || !Objects.equals(a.getDisplayName(), b.getDisplayName())
                || !Objects.equals(a.getNickName(), b.getNickName())
                || !Objects.equals(a.getProfileUrl(), b.getProfileUrl())
                || !Objects.equals(a.getTitle(), b.getTitle())
                || !Objects.equals(a.getUserType(), b.getUserType())
                || !Objects.equals(a.getPreferredLanguage(), b.getPreferredLanguage())
                || !Objects.equals(a.getLocale(), b.getLocale())
                || !Objects.equals(a.getTimezone(), b.getTimezone())
                || a.isActive() != b.isActive()
                || !Objects.equals(a.getPassword(), b.getPassword())
                || !Objects.equals(a.getEnterpriseEmployeeNumber(), b.getEnterpriseEmployeeNumber())
                || !Objects.equals(a.getEnterpriseCostCenter(), b.getEnterpriseCostCenter())
                || !Objects.equals(a.getEnterpriseOrganization(), b.getEnterpriseOrganization())
                || !Objects.equals(a.getEnterpriseDivision(), b.getEnterpriseDivision())
                || !Objects.equals(a.getEnterpriseDepartment(), b.getEnterpriseDepartment())
                || !Objects.equals(a.getEnterpriseManagerValue(), b.getEnterpriseManagerValue())
                || !Objects.equals(a.getEnterpriseManagerRef(), b.getEnterpriseManagerRef())
                || !Objects.equals(a.getEnterpriseManagerDisplay(), b.getEnterpriseManagerDisplay())
                || !Objects.equals(a.getEmails(), b.getEmails())
                || !Objects.equals(a.getPhoneNumbers(), b.getPhoneNumbers())
                || !Objects.equals(a.getAddresses(), b.getAddresses())
                || !Objects.equals(a.getEntitlements(), b.getEntitlements())
                || !Objects.equals(a.getRoles(), b.getRoles())
                || !Objects.equals(a.getIms(), b.getIms())
                || !Objects.equals(a.getPhotos(), b.getPhotos())
                || !Objects.equals(a.getX509Certificates(), b.getX509Certificates());
    }
}
