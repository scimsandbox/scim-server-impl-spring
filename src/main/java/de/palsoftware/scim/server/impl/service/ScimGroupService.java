package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.model.ScimGroupMembership;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.repository.ScimGroupMembershipRepository;
import de.palsoftware.scim.server.impl.repository.ScimGroupRepository;
import de.palsoftware.scim.server.impl.repository.ScimUserRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.filter.ScimFilterEvaluator;
import de.palsoftware.scim.server.impl.scim.filter.ScimFilterParser;
import de.palsoftware.scim.server.impl.scim.pagination.OffsetBasedPageRequest;
import de.palsoftware.scim.server.impl.scim.validation.ScimCanonicalizer;
import org.hibernate.Hibernate;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
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
    private static final String GROUP_SCHEMA_PREFIX = "urn:ietf:params:scim:schemas:core:2.0:group:";
    private static final Pattern MEMBER_EQ_FILTER = Pattern.compile(
            "^\\s*(value|type|display|\\$ref)\\s+eq\\s+\"([^\"]*)\"\\s*$",
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
    public ScimGroup createGroup(UUID workspaceId, Map<String, Object> input) {
        String displayName = ScimCanonicalizer.requireNullableString(input.get(KEY_DISPLAY_NAME), KEY_DISPLAY_NAME);
        if (displayName == null || displayName.isBlank()) {
            throw new ScimException(400, "invalidValue", KEY_DISPLAY_NAME + " is required");
        }

        if (groupRepository.findByDisplayNameAndWorkspaceId(displayName, workspaceId).isPresent()) {
            throw new ScimException(409, "uniqueness",
                    RESOURCE_TYPE_GROUP + " with " + KEY_DISPLAY_NAME + " '" + displayName + "' already exists");
        }

        String externalId = ScimCanonicalizer.requireNullableString(input.get(KEY_EXTERNAL_ID), KEY_EXTERNAL_ID);
        List<Map<String, Object>> members = castMembersOrNull(input.get(KEY_MEMBERS));

        Workspace ws = workspaceRepository.findById(workspaceId)
                .orElseThrow(() -> new ScimException(404, null, "Workspace not found"));

        ScimGroup group = new ScimGroup();
        group.setWorkspace(ws);
        group.setDisplayName(displayName);
        if (externalId != null) {
            group.setExternalId(externalId);
        }

        group = groupRepository.save(group);

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
        if (ScimFilterParser.containsValuePath(filter)) {
            ScimFilterParser.FilterNode ast = ScimFilterParser.parseAst(filter, false);
            String sortAttr = ScimFilterParser.resolveGroupSortAttribute(sortBy);
            boolean isDescending = "descending".equalsIgnoreCase(sortOrder);

            Specification<ScimGroup> wsSpec = ScimFilterParser.parseGroupFilter(null, workspaceId);
            List<ScimGroup> candidates = groupRepository.findAll(wsSpec);
            if (candidates == null) {
                candidates = Collections.emptyList();
            }

            List<ScimGroup> matched = new ArrayList<>();
            for (ScimGroup g : candidates) {
                Hibernate.initialize(g.getMembers());
                if (ScimFilterEvaluator.matchesGroup(g, ast)) {
                    matched.add(g);
                }
            }

            long totalResults = matched.size();
            if (count == 0) {
                return buildListResponse(Collections.emptyList(), totalResults, startIndex, 0);
            }

            matched.sort(buildGroupInMemoryComparator(sortAttr, isDescending));
            int offset = Math.max(0, startIndex - 1);
            List<ScimGroup> page = offset >= matched.size()
                    ? Collections.emptyList()
                    : matched.subList(offset, Math.min(offset + count, matched.size()));
            return buildListResponse(page, totalResults, startIndex, page.size());
        }

        Specification<ScimGroup> spec = ScimFilterParser.parseGroupFilter(filter, workspaceId);

        long totalResults = groupRepository.count(spec);

        if (count == 0) {
            return buildListResponse(Collections.emptyList(), totalResults, startIndex, 0);
        }

        String sortAttr = ScimFilterParser.resolveGroupSortAttribute(sortBy);
        boolean isDescending = "descending".equalsIgnoreCase(sortOrder);
        Sort.Order primaryOrder = isDescending
                ? Sort.Order.desc(sortAttr).nullsFirst()
                : Sort.Order.asc(sortAttr).nullsLast();
        if (!isGroupSortAttributeCaseExact(sortAttr)) {
            primaryOrder = primaryOrder.ignoreCase();
        }
        Sort.Order tieBreaker = isDescending ? Sort.Order.desc("id") : Sort.Order.asc("id");
        Sort sort = "id".equals(sortAttr) ? Sort.by(primaryOrder) : Sort.by(primaryOrder, tieBreaker);

        int offset = Math.max(0, startIndex - 1);
        Pageable pageable = new OffsetBasedPageRequest(offset, count, sort);
        Page<ScimGroup> resultPage = groupRepository.findAll(spec, pageable);

        List<ScimGroup> page = resultPage.getContent();
        page.forEach(g -> Hibernate.initialize(g.getMembers()));

        return buildListResponse(page, totalResults, startIndex, page.size());
    }

    public Comparator<ScimGroup> buildGroupInMemoryComparator(String sortAttr, boolean isDescending) {
        Comparator<ScimGroup> primary;
        if ("createdAt".equals(sortAttr) || "lastModified".equals(sortAttr)) {
            Comparator<java.time.Instant> cmp = Comparator.naturalOrder();
            primary = isDescending
                    ? Comparator.comparing(g -> "createdAt".equals(sortAttr) ? g.getCreatedAt() : g.getLastModified(),
                            Comparator.nullsFirst(cmp.reversed()))
                    : Comparator.comparing(g -> "createdAt".equals(sortAttr) ? g.getCreatedAt() : g.getLastModified(),
                            Comparator.nullsLast(cmp));
        } else {
            Comparator<String> strCmp = isGroupSortAttributeCaseExact(sortAttr)
                    ? Comparator.naturalOrder()
                    : String.CASE_INSENSITIVE_ORDER;
            primary = isDescending
                    ? Comparator.comparing(g -> extractGroupSortString(g, sortAttr), Comparator.nullsFirst(strCmp.reversed()))
                    : Comparator.comparing(g -> extractGroupSortString(g, sortAttr), Comparator.nullsLast(strCmp));
        }
        Comparator<String> idCmp = isDescending ? Comparator.reverseOrder() : Comparator.naturalOrder();
        return primary.thenComparing(g -> g.getId() != null ? g.getId().toString() : "", idCmp);
    }

    private String extractGroupSortString(ScimGroup g, String sortAttr) {
        return switch (sortAttr) {
            case "id" -> g.getId() != null ? g.getId().toString() : null;
            case "externalId" -> g.getExternalId();
            case "displayName" -> g.getDisplayName();
            default -> g.getDisplayName();
        };
    }

    private static boolean isGroupSortAttributeCaseExact(String sortAttr) {
        return switch (sortAttr) {
            case "id", "externalId", "createdAt", "lastModified" -> true;
            default -> false;
        };
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
    public ScimGroup replaceGroup(UUID workspaceId, UUID groupId, Map<String, Object> input, String ifMatch) {
        ScimGroup existing = getGroup(workspaceId, groupId);

        validateIfMatch(ifMatch, existing.getVersion());

        String displayName = ScimCanonicalizer.requireNullableString(input.get(KEY_DISPLAY_NAME), KEY_DISPLAY_NAME);
        if (displayName == null || displayName.isBlank()) {
            throw new ScimException(400, "invalidValue", KEY_DISPLAY_NAME + " is required");
        }

        // Check uniqueness if changed (excluding self in case of Hibernate flush)
        if (!existing.getDisplayName().equals(displayName)) {
            boolean conflict = groupRepository.findByDisplayNameAndWorkspaceId(displayName, workspaceId)
                    .filter(other -> !Objects.equals(other.getId(), existing.getId()))
                    .isPresent();
            if (conflict) {
                throw new ScimException(409, "uniqueness",
                        RESOURCE_TYPE_GROUP + " with " + KEY_DISPLAY_NAME + " '" + displayName + "' already exists");
            }
        }

        String externalId = ScimCanonicalizer.requireNullableString(input.get(KEY_EXTERNAL_ID), KEY_EXTERNAL_ID);
        List<Map<String, Object>> members = castMembersOrNull(input.get(KEY_MEMBERS));

        // GRP_21: RFC 7643 §4.2 & §7 - Group member sub-attributes 'value', 'type', and '$ref' are immutable
        if (members != null) {
            validateExistingMemberImmutability(existing.getMembers(), members);
        }

        // Validate all replacement members on a draft copy first so invalid inputs never clear existing members
        ScimGroup draft = copyGroup(existing);
        draft.setDisplayName(displayName);
        draft.setExternalId(externalId);
        draft.getMembers().clear();
        if (members != null) {
            for (Map<String, Object> m : members) {
                addMember(draft, workspaceId, m);
            }
        }

        existing.setDisplayName(displayName);
        existing.setExternalId(externalId);

        // Replace members entirely
        existing.getMembers().clear();
        groupRepository.saveAndFlush(existing);

        for (ScimGroupMembership desired : draft.getMembers()) {
            ScimGroupMembership nm = new ScimGroupMembership();
            nm.setGroup(existing);
            nm.setMemberValue(desired.getMemberValue());
            nm.setMemberType(desired.getMemberType());
            nm.setDisplay(desired.getDisplay());
            existing.getMembers().add(nm);
        }

        ScimGroup savedGroup = groupRepository.save(existing);
        workspaceActivityService.touchWorkspace(workspaceId);
        Hibernate.initialize(savedGroup.getMembers());
        return savedGroup;
    }

    @Transactional
    public ScimGroup patchGroup(UUID workspaceId, UUID groupId, List<Map<String, Object>> operations, String ifMatch) {
        ScimGroup group = getGroup(workspaceId, groupId);
        String originalDisplayName = group.getDisplayName();

        validateIfMatch(ifMatch, group.getVersion());

        ScimGroup draft = copyGroup(group);
        for (Map<String, Object> op : operations) {
            applyPatchOperation(draft, workspaceId, op);
        }

        if (draft.getDisplayName() == null || draft.getDisplayName().isBlank()) {
            throw new ScimException(400, "invalidValue", KEY_DISPLAY_NAME + " is required");
        }

        if (!draft.getDisplayName().equals(originalDisplayName)) {
            boolean conflict = groupRepository.findByDisplayNameAndWorkspaceId(draft.getDisplayName(), workspaceId)
                    .filter(other -> !Objects.equals(other.getId(), group.getId()))
                    .isPresent();
            if (conflict) {
                throw new ScimException(409, "uniqueness",
                        RESOURCE_TYPE_GROUP + " with " + KEY_DISPLAY_NAME + " '" + draft.getDisplayName() + "' already exists");
            }
        }

        if (!hasGroupChanged(group, draft)) {
            return group;
        }

        syncGroupState(draft, group);
        ScimGroup savedGroup = groupRepository.save(group);
        workspaceActivityService.touchWorkspace(workspaceId);
        Hibernate.initialize(savedGroup.getMembers());
        return savedGroup;
    }

    private void applyPatchOperation(ScimGroup group, UUID workspaceId, Map<String, Object> op) {
        Object opObj = op.get("op");
        if (!(opObj instanceof String opStr) || opStr.isBlank()) {
            throw new ScimException(400, "invalidValue", "PATCH operation 'op' must be a non-empty string");
        }
        String opType = opStr.trim().toLowerCase(Locale.ROOT);
        String rawPath = ScimCanonicalizer.requireNullableString(op.get("path"), "path");
        String normPath = normalizeGroupPath(rawPath);
        Object value = op.get(KEY_VALUE);

        if (normPath != null && isReadOnlyGroupPath(normPath)) {
            throw new ScimException(400, "mutability", "Attribute '" + rawPath + "' is readOnly and cannot be modified");
        }

        switch (opType) {
            case "add" -> {
                if (!op.containsKey(KEY_VALUE) || value == null) {
                    throw new ScimException(400, "invalidValue", "PATCH 'add' operation must contain a 'value' member");
                }
                applyAddOperation(group, workspaceId, normPath, rawPath, value);
            }
            case "replace" -> {
                if (!op.containsKey(KEY_VALUE)) {
                    throw new ScimException(400, "invalidValue", "PATCH 'replace' operation must contain a 'value' member");
                }
                applyReplaceOperation(group, workspaceId, normPath, rawPath, value);
            }
            case "remove" -> applyRemoveOperation(group, normPath, rawPath, value);
            default -> throw new ScimException(400, "invalidValue", "Unsupported PATCH op: " + opType);
        }
    }

    @SuppressWarnings("unchecked")
    private void applyAddOperation(ScimGroup group, UUID workspaceId, String normPath, String rawPath, Object value) {
        if (normPath == null) {
            if (value instanceof Map<?, ?> rawMap) {
                Map<String, Object> valueMap = (Map<String, Object>) rawMap;
                // Legacy single-member envelope support vs RFC 7644 §3.5.2.1 resource attribute map
                if ((valueMap.containsKey(KEY_VALUE) || valueMap.containsKey("$ref"))
                        && !valueMap.containsKey(KEY_DISPLAY_NAME)
                        && !valueMap.containsKey(KEY_EXTERNAL_ID)
                        && !valueMap.containsKey(KEY_MEMBERS)) {
                    addMissingMembers(group, workspaceId, List.of(valueMap));
                    return;
                }
                applyAddValueMap(group, workspaceId, valueMap);
                return;
            }
            if (value instanceof List<?>) {
                addMissingMembers(group, workspaceId, extractMembersPayload(value, true, "Invalid value for members add"));
                return;
            }
            throw new ScimException(400, "invalidValue", "PATCH 'add' without path requires a complex object value");
        }
        if (KEY_MEMBERS.equalsIgnoreCase(normPath)) {
            addMissingMembers(group, workspaceId, extractMembersPayload(value, true, "Invalid value for members add"));
            return;
        }
        if (KEY_DISPLAY_NAME.equalsIgnoreCase(normPath)) {
            String displayName = ScimCanonicalizer.requireNullableString(value, KEY_DISPLAY_NAME);
            if (displayName == null || displayName.isBlank()) {
                throw new ScimException(400, "invalidValue", KEY_DISPLAY_NAME + " is required");
            }
            updateDisplayName(group, workspaceId, displayName);
            return;
        }
        if (KEY_EXTERNAL_ID.equalsIgnoreCase(normPath)) {
            group.setExternalId(ScimCanonicalizer.requireNullableString(value, KEY_EXTERNAL_ID));
            return;
        }
        if (normPath.toLowerCase(Locale.ROOT).startsWith("members[")) {
            applyFilteredMemberAdd(group, workspaceId, normPath, rawPath, value);
            return;
        }
        if (isImmutableMemberSubPath(normPath)) {
            throw new ScimException(400, "mutability", "Attribute '" + rawPath + "' is immutable and cannot be modified");
        }
        throw new ScimException(400, "invalidPath", "Unknown Group attribute path: " + rawPath);
    }

    @SuppressWarnings("unchecked")
    private void applyReplaceOperation(ScimGroup group, UUID workspaceId, String normPath, String rawPath, Object value) {
        if (normPath == null) {
            if (!(value instanceof Map<?, ?> rawMap)) {
                throw new ScimException(400, "invalidValue", "PATCH 'replace' without path requires a complex object value");
            }
            applyReplaceValueMap(group, workspaceId, (Map<String, Object>) rawMap);
            return;
        }
        if (KEY_MEMBERS.equalsIgnoreCase(normPath)) {
            if (value == null) {
                group.getMembers().clear();
            } else {
                replaceMembers(group, workspaceId, extractMembersPayload(value, false, "Invalid value for members replace"));
            }
            return;
        }
        if (KEY_DISPLAY_NAME.equalsIgnoreCase(normPath)) {
            String displayName = ScimCanonicalizer.requireNullableString(value, KEY_DISPLAY_NAME);
            if (displayName == null || displayName.isBlank()) {
                throw new ScimException(400, "invalidValue", KEY_DISPLAY_NAME + " is required");
            }
            updateDisplayName(group, workspaceId, displayName);
            return;
        }
        if (KEY_EXTERNAL_ID.equalsIgnoreCase(normPath)) {
            group.setExternalId(ScimCanonicalizer.requireNullableString(value, KEY_EXTERNAL_ID));
            return;
        }
        if (normPath.toLowerCase(Locale.ROOT).startsWith("members[")) {
            applyFilteredMemberReplace(group, normPath, rawPath, value);
            return;
        }
        if (isImmutableMemberSubPath(normPath)) {
            throw new ScimException(400, "mutability", "Attribute '" + rawPath + "' is immutable and cannot be modified");
        }
        throw new ScimException(400, "invalidPath", "Unknown Group attribute path: " + rawPath);
    }

    private void applyRemoveOperation(ScimGroup group, String normPath, String rawPath, Object value) {
        if (normPath == null) {
            throw new ScimException(400, "noTarget", "PATCH 'remove' operation requires a 'path'");
        }
        if (KEY_DISPLAY_NAME.equalsIgnoreCase(normPath)) {
            throw new ScimException(400, "mutability", "Required attribute 'displayName' cannot be removed");
        }
        if (KEY_EXTERNAL_ID.equalsIgnoreCase(normPath)) {
            group.setExternalId(null);
            return;
        }
        if (KEY_MEMBERS.equalsIgnoreCase(normPath)) {
            if (value instanceof List<?>) {
                removeMembers(group, castMembers(value));
            } else if (value instanceof Map<?, ?> rawMap) {
                @SuppressWarnings("unchecked")
                Map<String, Object> m = (Map<String, Object>) rawMap;
                removeMembers(group, List.of(m));
            } else if (value == null) {
                group.getMembers().clear();
            } else {
                throw new ScimException(400, "invalidValue", "Invalid value for members remove");
            }
            return;
        }
        if (normPath.toLowerCase(Locale.ROOT).startsWith("members[")) {
            int closeIdx = findClosingBracketOutsideQuotes(normPath, 7);
            if (closeIdx < 0) {
                throw new ScimException(400, "invalidPath", "Unclosed bracket in path: " + rawPath);
            }
            String remainder = normPath.substring(closeIdx + 1).trim();
            if (!remainder.isEmpty()) {
                if (remainder.startsWith(".")) {
                    String sub = remainder.substring(1).toLowerCase(Locale.ROOT);
                    if ("value".equals(sub) || "type".equals(sub) || "$ref".equals(sub)) {
                        throw new ScimException(400, "mutability", "Member sub-attribute '" + sub + "' cannot be removed");
                    }
                    if ("display".equals(sub)) {
                        String filterExpr = normPath.substring(8, closeIdx);
                        for (ScimGroupMembership member : group.getMembers()) {
                            if (matchesMemberFilter(member, filterExpr, rawPath)) {
                                member.setDisplay(null);
                            }
                        }
                        return;
                    }
                }
                throw new ScimException(400, "invalidPath", "Invalid member path: " + rawPath);
            }
            String filterExpr = normPath.substring(8, closeIdx);
            // Validate syntax even when members list is empty
            validateMemberFilterSyntax(filterExpr, rawPath);
            group.getMembers().removeIf(member -> matchesMemberFilter(member, filterExpr, rawPath));
            return;
        }
        if (isImmutableMemberSubPath(normPath)) {
            throw new ScimException(400, "mutability", "Attribute '" + rawPath + "' is immutable and cannot be removed");
        }
        throw new ScimException(400, "invalidPath", "Unknown Group attribute path: " + rawPath);
    }

    @SuppressWarnings("unchecked")
    private void applyFilteredMemberAdd(ScimGroup group, UUID workspaceId, String normPath, String rawPath, Object value) {
        int closeIdx = findClosingBracketOutsideQuotes(normPath, 7);
        if (closeIdx < 0) {
            throw new ScimException(400, "invalidPath", "Unclosed bracket in path: " + rawPath);
        }
        String filterExpr = normPath.substring(8, closeIdx);
        validateMemberFilterSyntax(filterExpr, rawPath);
        String remainder = normPath.substring(closeIdx + 1).trim();
        String subAttr = remainder.startsWith(".") ? remainder.substring(1).trim() : (remainder.isEmpty() ? null : remainder);

        List<ScimGroupMembership> matched = new ArrayList<>();
        for (ScimGroupMembership m : group.getMembers()) {
            if (matchesMemberFilter(m, filterExpr, rawPath)) {
                matched.add(m);
            }
        }
        if (matched.isEmpty()) {
            throw new ScimException(400, "noTarget", "No matching member found for path: " + rawPath);
        }

        if (subAttr != null) {
            if ("type".equalsIgnoreCase(subAttr)) {
                String newType = ScimCanonicalizer.requireNullableString(value, "members.type");
                if (newType == null || newType.isBlank()) {
                    throw new ScimException(400, "invalidValue", "Member type must not be blank");
                }
                for (ScimGroupMembership m : matched) {
                    String existingType = m.getMemberType();
                    if (existingType == null || existingType.isBlank()) {
                        // RFC 7644 §3.5.2 (RFC7644-3.5.2-0cc87d): client MAY add a value to an immutable attribute if previously unset
                        String canonicalType = validateAndResolveExplicitMemberType(group, workspaceId, m.getMemberValue(), newType);
                        m.setMemberType(canonicalType);
                    } else if (!existingType.equalsIgnoreCase(newType.trim())) {
                        throw new ScimException(400, "mutability", "Group member 'type' is immutable");
                    }
                }
                return;
            }
            if ("value".equalsIgnoreCase(subAttr)) {
                String newVal = ScimCanonicalizer.requireNullableString(value, "members.value");
                for (ScimGroupMembership m : matched) {
                    if (newVal == null || !m.getMemberValue().toString().equalsIgnoreCase(newVal.trim())) {
                        throw new ScimException(400, "mutability", "Group member 'value' is immutable");
                    }
                }
                return;
            }
            if ("$ref".equalsIgnoreCase(subAttr)) {
                String newRef = ScimCanonicalizer.requireNullableString(value, "members.$ref");
                if (newRef != null && !newRef.isBlank()) {
                    extractValidatedMemberRefTail(newRef);
                }
                for (ScimGroupMembership m : matched) {
                    if (newRef == null || newRef.isBlank()
                            || !ScimCanonicalizer.scimRefsComparable(newRef, expectedMemberRefTail(m))) {
                        throw new ScimException(400, "mutability", "Group member '$ref' is immutable");
                    }
                }
                return;
            }
            if ("display".equalsIgnoreCase(subAttr)) {
                String disp = ScimCanonicalizer.requireNullableString(value, "members.display");
                for (ScimGroupMembership m : matched) {
                    m.setDisplay(disp);
                }
                return;
            }
            throw new ScimException(400, "invalidPath", "Unknown member sub-attribute: " + subAttr);
        }

        if (!(value instanceof Map<?, ?> rawMap)) {
            throw new ScimException(400, "invalidValue", "Filtered member add requires an object value");
        }
        Map<String, Object> memberMap = (Map<String, Object>) rawMap;
        String newVal = ScimCanonicalizer.requireNullableString(memberMap.get(KEY_VALUE), "members.value");
        String newType = ScimCanonicalizer.requireNullableString(memberMap.get("type"), "members.type");
        String newRef = ScimCanonicalizer.requireNullableString(memberMap.get("$ref"), "members.$ref");
        validatePartialMemberMapConsistency(newVal, newType, newRef);
        for (ScimGroupMembership m : matched) {
            if (memberMap.containsKey(KEY_VALUE)
                    && (newVal == null || !m.getMemberValue().toString().equalsIgnoreCase(newVal.trim()))) {
                throw new ScimException(400, "mutability", "Group member 'value' is immutable");
            }
            if (newType != null && !newType.isBlank()) {
                if (m.getMemberType() == null || m.getMemberType().isBlank()) {
                    m.setMemberType(validateAndResolveExplicitMemberType(group, workspaceId, m.getMemberValue(), newType));
                } else if (!m.getMemberType().equalsIgnoreCase(newType.trim())) {
                    throw new ScimException(400, "mutability", "Group member 'type' is immutable");
                }
            }
            if (memberMap.containsKey("$ref") && (newRef == null || newRef.isBlank()
                    || !ScimCanonicalizer.scimRefsComparable(newRef, expectedMemberRefTail(m)))) {
                throw new ScimException(400, "mutability", "Group member '$ref' is immutable");
            }
            if (memberMap.containsKey("display")) {
                m.setDisplay(ScimCanonicalizer.requireNullableString(memberMap.get("display"), "members.display"));
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void applyFilteredMemberReplace(ScimGroup group, String normPath, String rawPath, Object value) {
        int closeIdx = findClosingBracketOutsideQuotes(normPath, 7);
        if (closeIdx < 0) {
            throw new ScimException(400, "invalidPath", "Unclosed bracket in path: " + rawPath);
        }
        String filterExpr = normPath.substring(8, closeIdx);
        validateMemberFilterSyntax(filterExpr, rawPath);
        String remainder = normPath.substring(closeIdx + 1).trim();
        String subAttr = remainder.startsWith(".") ? remainder.substring(1).trim() : (remainder.isEmpty() ? null : remainder);

        List<ScimGroupMembership> matched = new ArrayList<>();
        for (ScimGroupMembership m : group.getMembers()) {
            if (matchesMemberFilter(m, filterExpr, rawPath)) {
                matched.add(m);
            }
        }
        if (matched.isEmpty()) {
            throw new ScimException(400, "noTarget", "No matching member found for path: " + rawPath);
        }

        if (subAttr != null) {
            if ("value".equalsIgnoreCase(subAttr)
                    || "type".equalsIgnoreCase(subAttr)
                    || "$ref".equalsIgnoreCase(subAttr)) {
                // RFC 7643 §7 (RFC7643-7-031493): immutable sub-attributes SHALL NOT be updated via replace
                throw new ScimException(400, "mutability", "Group member '" + subAttr + "' is immutable");
            }
            if ("display".equalsIgnoreCase(subAttr)) {
                String disp = ScimCanonicalizer.requireNullableString(value, "members.display");
                for (ScimGroupMembership m : matched) {
                    m.setDisplay(disp);
                }
                return;
            }
            throw new ScimException(400, "invalidPath", "Unknown member sub-attribute: " + subAttr);
        }

        if (!(value instanceof Map<?, ?> rawMap)) {
            throw new ScimException(400, "invalidValue", "Filtered member replace requires an object value");
        }
        Map<String, Object> memberMap = (Map<String, Object>) rawMap;
        String newVal = ScimCanonicalizer.requireNullableString(memberMap.get(KEY_VALUE), "members.value");
        String newType = ScimCanonicalizer.requireNullableString(memberMap.get("type"), "members.type");
        String newRef = ScimCanonicalizer.requireNullableString(memberMap.get("$ref"), "members.$ref");
        validatePartialMemberMapConsistency(newVal, newType, newRef);
        for (ScimGroupMembership m : matched) {
            if (memberMap.containsKey(KEY_VALUE)
                    && (newVal == null || !m.getMemberValue().toString().equalsIgnoreCase(newVal.trim()))) {
                throw new ScimException(400, "mutability", "Group member 'value' is immutable");
            }
            if (memberMap.containsKey("type")) {
                // RFC 7643 §7 & RFC 7644 §3.5.2: replace cannot mutate or initialize an unset immutable attribute
                if (newType == null || newType.isBlank()
                        || m.getMemberType() == null || m.getMemberType().isBlank()
                        || !m.getMemberType().equalsIgnoreCase(newType.trim())) {
                    throw new ScimException(400, "mutability", "Group member 'type' is immutable");
                }
            }
            if (memberMap.containsKey("$ref")
                    && (newRef == null || newRef.isBlank()
                    || !ScimCanonicalizer.scimRefsComparable(newRef, expectedMemberRefTail(m)))) {
                throw new ScimException(400, "mutability", "Group member '$ref' is immutable");
            }
            if (memberMap.containsKey("display")) {
                m.setDisplay(ScimCanonicalizer.requireNullableString(memberMap.get("display"), "members.display"));
            }
        }
    }

    private void applyAddValueMap(ScimGroup group, UUID workspaceId, Map<String, Object> valueMap) {
        for (Map.Entry<String, Object> entry : valueMap.entrySet()) {
            String key = normalizeGroupPath(entry.getKey());
            if (key == null) continue;
            if ("id".equalsIgnoreCase(key) || "schemas".equalsIgnoreCase(key) || "meta".equalsIgnoreCase(key)) {
                continue;
            }
            if (isReadOnlyGroupPath(key)) {
                throw new ScimException(400, "mutability", "Attribute '" + entry.getKey() + "' is readOnly");
            }
            if (KEY_DISPLAY_NAME.equalsIgnoreCase(key)) {
                String dn = ScimCanonicalizer.requireNullableString(entry.getValue(), KEY_DISPLAY_NAME);
                if (dn == null || dn.isBlank()) {
                    throw new ScimException(400, "invalidValue", KEY_DISPLAY_NAME + " is required");
                }
                updateDisplayName(group, workspaceId, dn);
            } else if (KEY_EXTERNAL_ID.equalsIgnoreCase(key)) {
                group.setExternalId(ScimCanonicalizer.requireNullableString(entry.getValue(), KEY_EXTERNAL_ID));
            } else if (KEY_MEMBERS.equalsIgnoreCase(key)) {
                addMissingMembers(group, workspaceId, castMembers(entry.getValue()));
            } else {
                throw new ScimException(400, "invalidPath", "Unknown Group attribute: " + entry.getKey());
            }
        }
    }

    private void applyReplaceValueMap(ScimGroup group, UUID workspaceId, Map<String, Object> valueMap) {
        for (Map.Entry<String, Object> entry : valueMap.entrySet()) {
            String key = normalizeGroupPath(entry.getKey());
            if (key == null) continue;
            if ("id".equalsIgnoreCase(key) || "schemas".equalsIgnoreCase(key) || "meta".equalsIgnoreCase(key)) {
                continue;
            }
            if (isReadOnlyGroupPath(key)) {
                throw new ScimException(400, "mutability", "Attribute '" + entry.getKey() + "' is readOnly");
            }
            if (KEY_DISPLAY_NAME.equalsIgnoreCase(key)) {
                String dn = ScimCanonicalizer.requireNullableString(entry.getValue(), KEY_DISPLAY_NAME);
                if (dn == null || dn.isBlank()) {
                    throw new ScimException(400, "invalidValue", KEY_DISPLAY_NAME + " is required");
                }
                updateDisplayName(group, workspaceId, dn);
            } else if (KEY_EXTERNAL_ID.equalsIgnoreCase(key)) {
                group.setExternalId(ScimCanonicalizer.requireNullableString(entry.getValue(), KEY_EXTERNAL_ID));
            } else if (KEY_MEMBERS.equalsIgnoreCase(key)) {
                replaceMembers(group, workspaceId, castMembers(entry.getValue()));
            } else {
                throw new ScimException(400, "invalidPath", "Unknown Group attribute: " + entry.getKey());
            }
        }
    }

    private void updateDisplayName(ScimGroup group, UUID workspaceId, String newName) {
        if (!Objects.equals(group.getDisplayName(), newName)) {
            boolean conflict = groupRepository.findByDisplayNameAndWorkspaceId(newName, workspaceId)
                    .filter(other -> !Objects.equals(other.getId(), group.getId()))
                    .isPresent();
            if (conflict) {
                throw new ScimException(409, "uniqueness",
                        RESOURCE_TYPE_GROUP + " with " + KEY_DISPLAY_NAME + " '" + newName + "' already exists");
            }
        }
        group.setDisplayName(newName);
    }

    private record ResolvedMemberInput(
            UUID memberId,
            String explicitType,
            String inferredType,
            String canonicalTail,
            String display) {
        String effectiveType() {
            return explicitType != null ? explicitType : inferredType;
        }
    }

    private static ResolvedMemberInput resolveMemberInput(Map<String, Object> memberMap) {
        if (memberMap == null) {
            throw new ScimException(400, "invalidValue", "Member entry must not be null");
        }
        String rawValue = ScimCanonicalizer.requireNullableString(memberMap.get(KEY_VALUE), "members.value");
        String rawType = ScimCanonicalizer.requireNullableString(memberMap.get("type"), "members.type");
        String rawRef = memberMap.containsKey("$ref")
                ? ScimCanonicalizer.requireNullableString(memberMap.get("$ref"), "members.$ref")
                : null;
        String rawDisplay = ScimCanonicalizer.requireNullableString(memberMap.get("display"), "members.display");

        String explicitType = null;
        if (rawType != null && !rawType.isBlank()) {
            String trimmedType = rawType.trim();
            if (RESOURCE_TYPE_USER.equalsIgnoreCase(trimmedType)) {
                explicitType = RESOURCE_TYPE_USER;
            } else if (RESOURCE_TYPE_GROUP.equalsIgnoreCase(trimmedType)) {
                explicitType = RESOURCE_TYPE_GROUP;
            } else {
                throw new ScimException(400, "invalidValue", "Invalid member type: " + rawType);
            }
        }

        UUID refMemberId = null;
        String inferredType = null;
        String canonicalTail = null;
        if (rawRef != null && !rawRef.isBlank()) {
            String tail = extractValidatedMemberRefTail(rawRef);
            int slash = tail.indexOf('/');
            String resourceSegment = tail.substring(0, slash);
            String idPart = tail.substring(slash + 1);
            inferredType = "Groups".equals(resourceSegment) ? RESOURCE_TYPE_GROUP : RESOURCE_TYPE_USER;
            refMemberId = parseStrictUuid(idPart, "Invalid member '$ref' resource ID (must be UUID): " + rawRef);
            canonicalTail = resourceSegment + "/" + refMemberId;
            if (explicitType != null && !explicitType.equalsIgnoreCase(inferredType)) {
                throw new ScimException(400, "invalidValue",
                        "Member '$ref' resource type conflicts with member 'type'");
            }
        }

        UUID memberId;
        if (rawValue != null && !rawValue.isBlank()) {
            UUID valueMemberId = parseStrictUuid(rawValue.trim(), "Invalid member value (must be UUID): " + rawValue);
            if (refMemberId != null && !valueMemberId.equals(refMemberId)) {
                throw new ScimException(400, "invalidValue",
                        "Member '$ref' does not match member 'value'");
            }
            memberId = valueMemberId;
        } else if (refMemberId != null) {
            memberId = refMemberId;
        } else {
            throw new ScimException(400, "invalidValue", "Member 'value' or '$ref' is required");
        }

        return new ResolvedMemberInput(memberId, explicitType, inferredType, canonicalTail, rawDisplay);
    }

    private static String extractValidatedMemberRefTail(String rawRef) {
        String normalizedRef;
        try {
            normalizedRef = new java.net.URI(rawRef.trim()).normalize().toString();
        } catch (java.net.URISyntaxException e) {
            throw new ScimException(400, "invalidValue", "Member '$ref' must be a valid URI", e);
        }
        String tail = ScimCanonicalizer.extractCanonicalScimResourceTail(normalizedRef);
        if (tail == null) {
            throw new ScimException(400, "invalidValue",
                    "Member '$ref' must reference a SCIM User or Group URI: " + rawRef);
        }
        return tail;
    }

    private static void validatePartialMemberMapConsistency(String rawVal, String rawType, String rawRef) {
        String explicitType = null;
        if (rawType != null && !rawType.isBlank()) {
            String trimmedType = rawType.trim();
            if (RESOURCE_TYPE_USER.equalsIgnoreCase(trimmedType)) {
                explicitType = RESOURCE_TYPE_USER;
            } else if (RESOURCE_TYPE_GROUP.equalsIgnoreCase(trimmedType)) {
                explicitType = RESOURCE_TYPE_GROUP;
            } else {
                throw new ScimException(400, "invalidValue", "Invalid member type: " + rawType);
            }
        }
        if (rawRef != null && !rawRef.isBlank()) {
            String tail = extractValidatedMemberRefTail(rawRef);
            int slash = tail.indexOf('/');
            String resourceSegment = tail.substring(0, slash);
            String idPart = tail.substring(slash + 1);
            String inferredType = "Groups".equals(resourceSegment) ? RESOURCE_TYPE_GROUP : RESOURCE_TYPE_USER;
            UUID refMemberId = parseStrictUuid(idPart, "Invalid member '$ref' resource ID (must be UUID): " + rawRef);
            if (explicitType != null && !explicitType.equalsIgnoreCase(inferredType)) {
                throw new ScimException(400, "invalidValue",
                        "Member '$ref' resource type conflicts with member 'type'");
            }
            if (rawVal != null && !rawVal.isBlank()) {
                UUID valMemberId = parseStrictUuid(rawVal.trim(), "Invalid member value (must be UUID): " + rawVal);
                if (!valMemberId.equals(refMemberId)) {
                    throw new ScimException(400, "invalidValue",
                            "Member '$ref' does not match member 'value'");
                }
            }
        }
    }

    private static UUID parseStrictUuid(String candidate, String errorMessage) {
        UUID parsed;
        try {
            parsed = UUID.fromString(candidate);
        } catch (IllegalArgumentException e) {
            throw new ScimException(400, "invalidValue", errorMessage, e);
        }
        if (candidate.length() != 36 || !parsed.toString().equalsIgnoreCase(candidate)) {
            throw new ScimException(400, "invalidValue", errorMessage);
        }
        return parsed;
    }

    private static int findClosingBracketOutsideQuotes(String s, int openIdx) {
        boolean inQuotes = false;
        for (int i = openIdx + 1; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && inQuotes && i + 1 < s.length()) {
                i++;
                continue;
            }
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == ']' && !inQuotes) {
                return i;
            }
        }
        return -1;
    }

    private void addMissingMembers(ScimGroup group, UUID workspaceId, List<Map<String, Object>> membersToAdd) {
        for (Map<String, Object> member : membersToAdd) {
            addMember(group, workspaceId, member);
        }
    }

    private void replaceMembers(ScimGroup group, UUID workspaceId, List<Map<String, Object>> newMembers) {
        validateExistingMemberImmutability(group.getMembers(), newMembers);
        group.getMembers().clear();
        for (Map<String, Object> member : newMembers) {
            addMember(group, workspaceId, member);
        }
    }

    private static void validateExistingMemberImmutability(List<ScimGroupMembership> existingMembers,
                                                           List<Map<String, Object>> incomingMembers) {
        Map<UUID, ScimGroupMembership> existingById = new HashMap<>();
        if (existingMembers != null) {
            for (ScimGroupMembership existing : existingMembers) {
                existingById.put(existing.getMemberValue(), existing);
            }
        }
        for (Map<String, Object> m : incomingMembers) {
            ResolvedMemberInput resolved = resolveMemberInput(m);
            ScimGroupMembership prev = existingById.get(resolved.memberId());
            if (prev == null) {
                continue;
            }
            String prevType = prev.getMemberType();
            if (prevType != null && !prevType.isBlank()) {
                if (resolved.explicitType() != null && !prevType.equalsIgnoreCase(resolved.explicitType())) {
                    throw new ScimException(400, "mutability",
                            "Group member type is immutable and cannot be changed for member: " + resolved.memberId());
                }
                if (resolved.canonicalTail() != null
                        && !ScimCanonicalizer.scimRefsComparable(resolved.canonicalTail(), expectedMemberRefTail(prev))) {
                    throw new ScimException(400, "mutability",
                            "Group member '$ref' is immutable and cannot be changed for member: " + resolved.memberId());
                }
            }
        }
    }

    private String validateAndResolveExplicitMemberType(ScimGroup group, UUID workspaceId, UUID memberId, String rawType) {
        String trimmedType = rawType.trim();
        if (RESOURCE_TYPE_USER.equalsIgnoreCase(trimmedType)) {
            userRepository.findByIdAndWorkspaceId(memberId, workspaceId)
                    .orElseThrow(() -> new ScimException(404, "invalidValue",
                            RESOURCE_TYPE_USER + " not found: " + memberId));
            return RESOURCE_TYPE_USER;
        }
        if (RESOURCE_TYPE_GROUP.equalsIgnoreCase(trimmedType)) {
            Optional<ScimGroup> grpOpt = groupRepository.findByIdAndWorkspaceId(memberId, workspaceId);
            if ((grpOpt == null || grpOpt.isEmpty()) && !Objects.equals(group.getId(), memberId)) {
                throw new ScimException(404, "invalidValue",
                        RESOURCE_TYPE_GROUP + " not found: " + memberId);
            }
            return RESOURCE_TYPE_GROUP;
        }
        throw new ScimException(400, "invalidValue", "Invalid member type: " + rawType);
    }

    private static String expectedMemberRefTail(ScimGroupMembership member) {
        String t = member.getMemberType();
        String resourceSegment = (t != null && RESOURCE_TYPE_GROUP.equalsIgnoreCase(t)) ? "/Groups/" : "/Users/";
        return resourceSegment + member.getMemberValue();
    }

    private static boolean isImmutableMemberSubPath(String normPath) {
        String lower = normPath.toLowerCase(Locale.ROOT);
        return "members.value".equals(lower)
                || "members.type".equals(lower)
                || "members.$ref".equals(lower);
    }

    private void removeMembers(ScimGroup group, List<Map<String, Object>> membersToRemove) {
        for (Map<String, Object> member : membersToRemove) {
            ResolvedMemberInput resolved = resolveMemberInput(member);
            String effType = resolved.effectiveType();
            group.getMembers().removeIf(existing -> {
                if (!resolved.memberId().equals(existing.getMemberValue())) {
                    return false;
                }
                if (effType != null && existing.getMemberType() != null && !existing.getMemberType().isBlank()) {
                    return existing.getMemberType().equalsIgnoreCase(effType);
                }
                return true;
            });
        }
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> extractMembersPayload(Object value, boolean allowEnvelope, String errorMessage) {
        if (value instanceof List<?> rawList) {
            return castMembers(rawList);
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
    private List<Map<String, Object>> castMembersOrNull(Object value) {
        if (value == null) {
            return null;
        }
        return castMembers(value);
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> castMembers(Object value) {
        if (value == null) {
            return List.of();
        }
        if (value instanceof List<?> rawList) {
            List<Map<String, Object>> result = new ArrayList<>(rawList.size());
            for (Object elem : rawList) {
                if (!(elem instanceof Map<?, ?> map)) {
                    throw new ScimException(400, "invalidValue", "Each member entry must be a complex object");
                }
                result.add((Map<String, Object>) map);
            }
            return result;
        }
        throw new ScimException(400, "invalidValue", "Invalid members payload");
    }

    @Transactional
    public void deleteGroup(UUID workspaceId, UUID groupId) {
        deleteGroup(workspaceId, groupId, null);
    }

    @Transactional
    public void deleteGroup(UUID workspaceId, UUID groupId, String ifMatch) {
        ScimGroup group = getGroup(workspaceId, groupId);
        validateIfMatch(ifMatch, group.getVersion());
        membershipRepository.deleteByMemberValue(groupId);
        groupRepository.delete(group);
        workspaceActivityService.touchWorkspace(workspaceId);
    }

    private void addMember(ScimGroup group, UUID workspaceId, Map<String, Object> memberMap) {
        ResolvedMemberInput resolved = resolveMemberInput(memberMap);
        UUID memberId = resolved.memberId();

        // Check existing/duplicate member AFTER full input validation so conflicting duplicates fail with 400
        ScimGroupMembership existing = group.getMembers().stream()
                .filter(m -> memberId.equals(m.getMemberValue()))
                .findFirst()
                .orElse(null);
        if (existing != null) {
            String existingType = existing.getMemberType();
            String effType = resolved.effectiveType();
            if (effType != null) {
                if (existingType == null || existingType.isBlank()) {
                    existing.setMemberType(validateAndResolveExplicitMemberType(group, workspaceId, memberId, effType));
                } else if (!existingType.equalsIgnoreCase(effType)) {
                    throw new ScimException(400, "invalidValue",
                            "Conflicting member 'type' or '$ref' for member: " + memberId);
                }
            }
            if (resolved.canonicalTail() != null && existing.getMemberType() != null && !existing.getMemberType().isBlank()
                    && !ScimCanonicalizer.scimRefsComparable(resolved.canonicalTail(), expectedMemberRefTail(existing))) {
                throw new ScimException(400, "invalidValue",
                        "Conflicting member '$ref' for member: " + memberId);
            }
            return;
        }

        String memberType;
        String resolvedDisplay;

        if (resolved.explicitType() != null) {
            if (RESOURCE_TYPE_USER.equalsIgnoreCase(resolved.explicitType())) {
                memberType = RESOURCE_TYPE_USER;
                ScimUser resolvedUser = userRepository.findByIdAndWorkspaceId(memberId, workspaceId)
                        .orElseThrow(() -> new ScimException(404, "invalidValue",
                                RESOURCE_TYPE_USER + " not found: " + memberId));
                resolvedDisplay = resolvedUser.getDisplayName() != null
                        ? resolvedUser.getDisplayName()
                        : resolvedUser.getUserName();
            } else {
                memberType = RESOURCE_TYPE_GROUP;
                ScimGroup resolvedGroup = findGroupOrSelf(group, workspaceId, memberId)
                        .orElseThrow(() -> new ScimException(404, "invalidValue",
                                RESOURCE_TYPE_GROUP + " not found: " + memberId));
                resolvedDisplay = resolvedGroup.getDisplayName();
            }
        } else if (resolved.inferredType() != null) {
            if (RESOURCE_TYPE_USER.equalsIgnoreCase(resolved.inferredType())) {
                Optional<ScimUser> userOpt = userRepository.findByIdAndWorkspaceId(memberId, workspaceId);
                if (userOpt != null && userOpt.isPresent()) {
                    memberType = RESOURCE_TYPE_USER;
                    ScimUser resolvedUser = userOpt.get();
                    resolvedDisplay = resolvedUser.getDisplayName() != null
                            ? resolvedUser.getDisplayName()
                            : resolvedUser.getUserName();
                } else if (findGroupOrSelf(group, workspaceId, memberId).isPresent()) {
                    throw new ScimException(400, "invalidValue",
                            "Member '$ref' points to Users/" + memberId + " but target resource is a Group");
                } else {
                    throw new ScimException(404, "invalidValue",
                            RESOURCE_TYPE_USER + " not found: " + memberId);
                }
            } else {
                Optional<ScimGroup> grpOpt = findGroupOrSelf(group, workspaceId, memberId);
                if (grpOpt.isPresent()) {
                    memberType = RESOURCE_TYPE_GROUP;
                    resolvedDisplay = grpOpt.get().getDisplayName();
                } else {
                    Optional<ScimUser> userOpt = userRepository.findByIdAndWorkspaceId(memberId, workspaceId);
                    if (userOpt != null && userOpt.isPresent()) {
                        throw new ScimException(400, "invalidValue",
                                "Member '$ref' points to Groups/" + memberId + " but target resource is a User");
                    }
                    throw new ScimException(404, "invalidValue",
                            RESOURCE_TYPE_GROUP + " not found: " + memberId);
                }
            }
        } else {
            // When both 'type' and '$ref' are omitted, check User first, then Group within the same workspace
            Optional<ScimUser> userOpt = userRepository.findByIdAndWorkspaceId(memberId, workspaceId);
            if (userOpt != null && userOpt.isPresent()) {
                memberType = RESOURCE_TYPE_USER;
                ScimUser resolvedUser = userOpt.get();
                resolvedDisplay = resolvedUser.getDisplayName() != null
                        ? resolvedUser.getDisplayName()
                        : resolvedUser.getUserName();
            } else {
                Optional<ScimGroup> grpOpt = findGroupOrSelf(group, workspaceId, memberId);
                if (grpOpt.isPresent()) {
                    memberType = RESOURCE_TYPE_GROUP;
                    resolvedDisplay = grpOpt.get().getDisplayName();
                } else {
                    throw new ScimException(404, "invalidValue",
                            RESOURCE_TYPE_USER + " not found: " + memberId);
                }
            }
        }

        ScimGroupMembership membership = new ScimGroupMembership();
        membership.setGroup(group);
        membership.setMemberValue(memberId);
        membership.setMemberType(memberType);
        membership.setDisplay(resolved.display() != null ? resolved.display() : resolvedDisplay);

        group.getMembers().add(membership);
    }

    private Optional<ScimGroup> findGroupOrSelf(ScimGroup currentGroup, UUID workspaceId, UUID candidateId) {
        Optional<ScimGroup> grpOpt = groupRepository.findByIdAndWorkspaceId(candidateId, workspaceId);
        if (grpOpt != null && grpOpt.isPresent()) {
            return grpOpt;
        }
        if (Objects.equals(currentGroup.getId(), candidateId)) {
            return Optional.of(currentGroup);
        }
        return Optional.empty();
    }

    private static String normalizeGroupPath(String rawPath) {
        if (rawPath == null || rawPath.isBlank()) {
            return null;
        }
        String trimmed = rawPath.trim();
        if (trimmed.toLowerCase(Locale.ROOT).startsWith(GROUP_SCHEMA_PREFIX)) {
            String stripped = trimmed.substring(GROUP_SCHEMA_PREFIX.length());
            return stripped.isBlank() ? null : stripped;
        }
        return trimmed;
    }

    private static boolean isReadOnlyGroupPath(String normPath) {
        String lower = normPath.toLowerCase(Locale.ROOT);
        return "id".equals(lower)
                || "schemas".equals(lower)
                || "meta".equals(lower)
                || lower.startsWith("meta.")
                || "groups".equals(lower)
                || lower.startsWith("groups.");
    }

    private static void validateMemberFilterSyntax(String filterExpr, String rawPath) {
        if (filterExpr == null || !MEMBER_EQ_FILTER.matcher(filterExpr).matches()) {
            throw new ScimException(400, "invalidFilter", "Invalid member filter in path: " + rawPath);
        }
    }

    private static boolean matchesMemberFilter(ScimGroupMembership member, String filterExpr, String rawPath) {
        Matcher m = MEMBER_EQ_FILTER.matcher(filterExpr);
        if (!m.matches()) {
            throw new ScimException(400, "invalidFilter", "Invalid member filter in path: " + rawPath);
        }
        String attr = m.group(1).toLowerCase(Locale.ROOT);
        String target = ScimCanonicalizer.normalizeNfc(m.group(2));
        return switch (attr) {
            case "value" -> member.getMemberValue() != null && member.getMemberValue().toString().equalsIgnoreCase(target);
            case "type" -> member.getMemberType() != null && member.getMemberType().equalsIgnoreCase(target);
            case "display" -> member.getDisplay() != null && member.getDisplay().equalsIgnoreCase(target);
            case "$ref" -> member.getMemberValue() != null && ScimCanonicalizer.scimRefsComparable(target, expectedMemberRefTail(member));
            default -> false;
        };
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

    private static ScimGroup copyGroup(ScimGroup src) {
        ScimGroup copy = new ScimGroup();
        copy.setId(src.getId());
        copy.setWorkspace(src.getWorkspace());
        copy.setDisplayName(src.getDisplayName());
        copy.setExternalId(src.getExternalId());
        copy.setCreatedAt(src.getCreatedAt());
        copy.setLastModified(src.getLastModified());
        copy.setVersion(src.getVersion());
        List<ScimGroupMembership> copiedMembers = new ArrayList<>();
        if (src.getMembers() != null) {
            for (ScimGroupMembership m : src.getMembers()) {
                ScimGroupMembership cm = new ScimGroupMembership();
                cm.setGroup(copy);
                cm.setMemberValue(m.getMemberValue());
                cm.setMemberType(m.getMemberType());
                cm.setDisplay(m.getDisplay());
                copiedMembers.add(cm);
            }
        }
        copy.setMembers(copiedMembers);
        return copy;
    }

    private static boolean hasGroupChanged(ScimGroup a, ScimGroup b) {
        if (!Objects.equals(a.getDisplayName(), b.getDisplayName())
                || !Objects.equals(a.getExternalId(), b.getExternalId())) {
            return true;
        }
        List<ScimGroupMembership> ma = a.getMembers() != null ? a.getMembers() : Collections.emptyList();
        List<ScimGroupMembership> mb = b.getMembers() != null ? b.getMembers() : Collections.emptyList();
        if (ma.size() != mb.size()) {
            return true;
        }
        for (int i = 0; i < ma.size(); i++) {
            ScimGroupMembership x = ma.get(i);
            ScimGroupMembership y = mb.get(i);
            if (!Objects.equals(x.getMemberValue(), y.getMemberValue())
                    || !Objects.equals(x.getMemberType(), y.getMemberType())
                    || !Objects.equals(x.getDisplay(), y.getDisplay())) {
                return true;
            }
        }
        return false;
    }

    private static void syncGroupState(ScimGroup src, ScimGroup dst) {
        dst.setDisplayName(src.getDisplayName());
        dst.setExternalId(src.getExternalId());

        Map<UUID, ScimGroupMembership> desiredByMemberId = new LinkedHashMap<>();
        for (ScimGroupMembership m : src.getMembers()) {
            desiredByMemberId.put(m.getMemberValue(), m);
        }

        // Remove deleted members and update existing members in place
        Set<UUID> retainedIds = new HashSet<>();
        Iterator<ScimGroupMembership> it = dst.getMembers().iterator();
        while (it.hasNext()) {
            ScimGroupMembership existing = it.next();
            ScimGroupMembership desired = desiredByMemberId.get(existing.getMemberValue());
            if (desired == null) {
                it.remove();
            } else {
                existing.setMemberType(desired.getMemberType());
                existing.setDisplay(desired.getDisplay());
                retainedIds.add(existing.getMemberValue());
            }
        }

        // Add newly added members
        for (ScimGroupMembership desired : src.getMembers()) {
            if (!retainedIds.contains(desired.getMemberValue())) {
                ScimGroupMembership nm = new ScimGroupMembership();
                nm.setGroup(dst);
                nm.setMemberValue(desired.getMemberValue());
                nm.setMemberType(desired.getMemberType());
                nm.setDisplay(desired.getDisplay());
                dst.getMembers().add(nm);
            }
        }
    }
}
