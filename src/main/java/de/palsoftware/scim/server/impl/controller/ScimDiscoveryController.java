package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.scim.compat.CompatMode;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.filter.ScimFilterParser;
import de.palsoftware.scim.server.impl.scim.mapper.ScimGroupMapper;
import de.palsoftware.scim.server.impl.scim.mapper.ScimUserMapper;
import de.palsoftware.scim.server.impl.scim.pagination.ScimCursorCodec;
import de.palsoftware.scim.server.impl.scim.schema.ScimSchemaDefinitions;
import de.palsoftware.scim.server.impl.service.ScimGroupService;
import de.palsoftware.scim.server.impl.service.ScimUserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.regex.Pattern;

/**
 * SCIM 2.0 Discovery Endpoints per RFC 7643 §5/§6/§7 and Root Query/Search per RFC 7644 §3.4.2.1/§3.4.3.
 * - /ServiceProviderConfig
 * - /Schemas, /Schemas/{id}
 * - /ResourceTypes, /ResourceTypes/{id}
 * - GET /, POST /.search (Root-level cross-resource query)
 */
@RestController
@RequestMapping({"/ws/{workspaceId}/scim/v2", "/ws/{workspaceId}/scim/v2/{compat}"})
public class ScimDiscoveryController extends ScimBaseController {

    private final ScimUserService userService;
    private final ScimGroupService groupService;

    public ScimDiscoveryController(ScimUserService userService, ScimGroupService groupService) {
        this.userService = userService;
        this.groupService = groupService;
    }

    // ─── ServiceProviderConfig ──────────────────────────────────────────

    @GetMapping("/ServiceProviderConfig")
    public ResponseEntity<Map<String, Object>> getServiceProviderConfig(
            @PathVariable(name = "compat", required = false) String compat,
            @RequestParam(name = "filter", required = false) String filter) {
        rejectDiscoveryFilter(filter);
        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .body(ScimSchemaDefinitions.serviceProviderConfig());
    }

    @RequestMapping(value = "/ServiceProviderConfig", method = {RequestMethod.POST, RequestMethod.PUT,
            RequestMethod.PATCH, RequestMethod.DELETE})
    public ResponseEntity<Map<String, Object>> serviceProviderConfigMethodNotAllowed(
            @PathVariable(name = "compat", required = false) String compat) {
        return methodNotAllowed();
    }

    // ─── Schemas ────────────────────────────────────────────────────────

    @GetMapping("/Schemas")
    public ResponseEntity<Map<String, Object>> getSchemas(
            @PathVariable(name = "compat", required = false) String compat,
            @RequestParam(name = "filter", required = false) String filter) {
        rejectDiscoveryFilter(filter);
        List<Map<String, Object>> schemas = ScimSchemaDefinitions.allSchemas();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put(KEY_SCHEMAS, List.of("urn:ietf:params:scim:api:messages:2.0:ListResponse"));
        response.put("totalResults", schemas.size());
        response.put("itemsPerPage", schemas.size());
        response.put("startIndex", 1);
        response.put("Resources", schemas);
        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .body(response);
    }

    @GetMapping("/Schemas/{schemaId}")
        public ResponseEntity<Map<String, Object>> getSchemaById(
            @PathVariable String schemaId,
            @PathVariable(name = "compat", required = false) String compat) {
        // The schema ID is a URN like urn:ietf:params:scim:schemas:core:2.0:User
        // but Spring URL-decodes it, so colons should be preserved
        Map<String, Object> schema = ScimSchemaDefinitions.getSchemaById(schemaId);
        if (schema == null) {
            throw new ScimException(404, null, "Schema not found: " + schemaId);
        }
        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .body(schema);
    }

    @RequestMapping(value = {"/Schemas", "/Schemas/{schemaId}"}, method = {RequestMethod.POST,
            RequestMethod.PUT, RequestMethod.PATCH, RequestMethod.DELETE})
    public ResponseEntity<Map<String, Object>> schemasMethodNotAllowed(
            @PathVariable(name = "schemaId", required = false) String schemaId,
            @PathVariable(name = "compat", required = false) String compat) {
        return methodNotAllowed();
    }

    // ─── ResourceTypes ──────────────────────────────────────────────────

    @GetMapping("/ResourceTypes")
    public ResponseEntity<Map<String, Object>> getResourceTypes(HttpServletRequest request,
            @PathVariable String workspaceId,
            @PathVariable(name = "compat", required = false) String compat,
            @RequestParam(name = "filter", required = false) String filter) {
        rejectDiscoveryFilter(filter);
        String baseUrl = buildBaseUrl(request, workspaceId, compat);
        List<Map<String, Object>> types = ScimSchemaDefinitions.resourceTypes(baseUrl);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put(KEY_SCHEMAS, List.of("urn:ietf:params:scim:api:messages:2.0:ListResponse"));
        response.put("totalResults", types.size());
        response.put("itemsPerPage", types.size());
        response.put("startIndex", 1);
        response.put("Resources", types);
        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .body(response);
    }

    private static void rejectDiscoveryFilter(String filter) {
        if (filter != null && !filter.isBlank()) {
            throw new ScimException(403, null, "Filtering is not supported on discovery endpoints");
        }
    }

    @GetMapping("/ResourceTypes/{resourceTypeId}")
    public ResponseEntity<Map<String, Object>> getResourceTypeById(@PathVariable String resourceTypeId,
            HttpServletRequest request, @PathVariable String workspaceId,
            @PathVariable(name = "compat", required = false) String compat) {
        String baseUrl = buildBaseUrl(request, workspaceId, compat);
        Map<String, Object> rt = ScimSchemaDefinitions.getResourceTypeById(resourceTypeId, baseUrl);
        if (rt == null) {
            throw new ScimException(404, null, "ResourceType not found: " + resourceTypeId);
        }
        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .body(rt);
    }

    @RequestMapping(value = {"/ResourceTypes", "/ResourceTypes/{resourceTypeId}"}, method = {RequestMethod.POST,
            RequestMethod.PUT, RequestMethod.PATCH, RequestMethod.DELETE})
    public ResponseEntity<Map<String, Object>> resourceTypesMethodNotAllowed(
            @PathVariable(name = "resourceTypeId", required = false) String resourceTypeId,
            @PathVariable(name = "compat", required = false) String compat) {
        return methodNotAllowed();
    }

    // ─── Root-Level Query & Global Search (RFC 7644 §3.4.2.1 / §3.4.3) ──

    @GetMapping({"", "/"})
    public ResponseEntity<Map<String, Object>> rootSearchGet(
            @PathVariable String workspaceId,
            @RequestParam(required = false) String filter,
            @RequestParam(required = false) Integer startIndex,
            @RequestParam(required = false, defaultValue = "100") int count,
            @RequestParam(required = false) String cursor,
            @RequestParam(required = false) String sortBy,
            @RequestParam(required = false, defaultValue = "ascending") String sortOrder,
            @RequestParam(required = false) String attributes,
            @RequestParam(required = false) String excludedAttributes,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        if (cursor != null && startIndex != null) {
            throw new ScimException(400, "invalidValue", "Cannot specify both cursor and startIndex");
        }

        return executeRootSearch(workspaceId, filter, sortBy, sortOrder, startIndex, count, cursor,
                attributes, excludedAttributes, compat, request);
    }

    @PostMapping("/.search")
    public ResponseEntity<Map<String, Object>> rootSearchPost(
            @PathVariable String workspaceId,
            @RequestBody(required = false) Map<String, Object> body,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        Map<String, Object> reqBody = body != null ? body : Collections.emptyMap();

        String filter = null;
        Object filterObj = reqBody.get("filter");
        if (filterObj instanceof String s) {
            filter = s;
        }

        String sortBy = null;
        Object sortByObj = reqBody.get("sortBy");
        if (sortByObj instanceof String s && !s.isBlank()) {
            sortBy = s;
        }

        String sortOrder = "ascending";
        Object sortOrderObj = reqBody.get("sortOrder");
        if (sortOrderObj instanceof String s && !s.isBlank()) {
            sortOrder = s;
        }

        String cursor = extractOptionalStringParam(reqBody, "cursor");
        Integer startIndex = extractOptionalIntParam(reqBody, "startIndex");

        if (cursor != null && startIndex != null) {
            throw new ScimException(400, "invalidValue", "Cannot specify both cursor and startIndex");
        }

        Integer countParam = extractOptionalIntParam(reqBody, "count");
        int count = countParam != null ? countParam : 100;

        String attributes = extractAttributesParam(reqBody.get("attributes"));
        String excludedAttributes = extractAttributesParam(reqBody.get("excludedAttributes"));

        return executeRootSearch(workspaceId, filter, sortBy, sortOrder, startIndex, count, cursor,
                attributes, excludedAttributes, compat, request);
    }

    @RequestMapping(value = {"", "/"}, method = {RequestMethod.POST, RequestMethod.PUT,
            RequestMethod.PATCH, RequestMethod.DELETE})
    public ResponseEntity<Map<String, Object>> rootMethodNotAllowed(
            @PathVariable(name = "compat", required = false) String compat) {
        if (compat != null && !compat.isBlank() && CompatMode.fromString(compat) == CompatMode.NONE) {
            throw new ScimException(404, null, "Resource or endpoint not found: " + compat);
        }
        return methodNotAllowed();
    }

    @RequestMapping(value = "/.search", method = {RequestMethod.GET, RequestMethod.PUT,
            RequestMethod.PATCH, RequestMethod.DELETE})
    public ResponseEntity<Map<String, Object>> searchMethodNotAllowed(
            @PathVariable(name = "compat", required = false) String compat) {
        if (compat != null && !compat.isBlank() && CompatMode.fromString(compat) == CompatMode.NONE) {
            throw new ScimException(404, null, "Resource or endpoint not found: " + compat);
        }
        return methodNotAllowed("POST");
    }

    // ─── Helpers ────────────────────────────────────────────────────────

    private static final Pattern USER_TYPE_PATTERN = Pattern.compile(
            "(?i)^(?:urn:ietf:params:scim:schemas:core:2\\.0:(?:User|Group):)?meta\\.resourceType\\s+eq\\s+[\"']?User[\"']?$"
    );
    private static final Pattern GROUP_TYPE_PATTERN = Pattern.compile(
            "(?i)^(?:urn:ietf:params:scim:schemas:core:2\\.0:(?:User|Group):)?meta\\.resourceType\\s+eq\\s+[\"']?Group[\"']?$"
    );
    private static final Pattern NOT_USER_TYPE_PATTERN = Pattern.compile(
            "(?i)^(?:urn:ietf:params:scim:schemas:core:2\\.0:(?:User|Group):)?meta\\.resourceType\\s+ne\\s+[\"']?User[\"']?$"
    );
    private static final Pattern NOT_GROUP_TYPE_PATTERN = Pattern.compile(
            "(?i)^(?:urn:ietf:params:scim:schemas:core:2\\.0:(?:User|Group):)?meta\\.resourceType\\s+ne\\s+[\"']?Group[\"']?$"
    );

    private static class TargetResourceTypes {
        final boolean users;
        final boolean groups;

        TargetResourceTypes(boolean users, boolean groups) {
            this.users = users;
            this.groups = groups;
        }
    }

    private static TargetResourceTypes resolveTargetResourceTypes(String filter) {
        if (filter == null || filter.isBlank()) {
            return new TargetResourceTypes(true, true);
        }
        String unwrapped = stripOuterParentheses(filter);
        if (USER_TYPE_PATTERN.matcher(unwrapped).matches() || NOT_GROUP_TYPE_PATTERN.matcher(unwrapped).matches()) {
            return new TargetResourceTypes(true, false);
        }
        if (GROUP_TYPE_PATTERN.matcher(unwrapped).matches() || NOT_USER_TYPE_PATTERN.matcher(unwrapped).matches()) {
            return new TargetResourceTypes(false, true);
        }
        return new TargetResourceTypes(true, true);
    }

    private static String stripOuterParentheses(String filter) {
        String s = filter.trim();
        while (s.length() >= 2 && s.charAt(0) == '(' && s.charAt(s.length() - 1) == ')') {
            int depth = 0;
            boolean inQuotes = false;
            boolean wrapsEntireExpression = true;
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c == '"' && (i == 0 || s.charAt(i - 1) != '\\')) {
                    inQuotes = !inQuotes;
                } else if (!inQuotes) {
                    if (c == '(') {
                        depth++;
                    } else if (c == ')') {
                        depth--;
                        if (depth == 0 && i < s.length() - 1) {
                            wrapsEntireExpression = false;
                            break;
                        }
                        if (depth < 0) {
                            return s;
                        }
                    }
                }
            }
            if (!wrapsEntireExpression || depth != 0 || inQuotes) {
                break;
            }
            s = s.substring(1, s.length() - 1).trim();
        }
        return s;
    }

    private static boolean isAttributeAbsenceError(ScimException e) {
        if (e.getHttpStatus() == 400 && "invalidFilter".equals(e.getScimType())) {
            String msg = e.getMessage();
            return msg != null && (
                    msg.contains("Unknown attribute") ||
                    msg.contains("Unknown meta attribute") ||
                    msg.contains("Unknown enterprise attribute") ||
                    msg.contains("Unknown name sub-attribute")
            );
        }
        return false;
    }

    private ResponseEntity<Map<String, Object>> executeRootSearch(
            String workspaceId,
            String filter,
            String sortBy,
            String sortOrder,
            Integer startIndex,
            int count,
            String cursor,
            String attributes,
            String excludedAttributes,
            String compat,
            HttpServletRequest request) {

        if (compat != null && !compat.isBlank() && CompatMode.fromString(compat) == CompatMode.NONE) {
            throw new ScimException(404, null, "Resource or endpoint not found: " + compat);
        }

        UUID wsId = resolveWorkspaceId(workspaceId);
        String baseUrl = buildBaseUrl(request, workspaceId);
        String compatBaseUrl = buildBaseUrl(request, workspaceId, compat);
        CompatMode compatMode = CompatMode.fromString(compat);

        if (cursor != null && startIndex != null) {
            throw new ScimException(400, "invalidValue", "Cannot specify both cursor and startIndex");
        }

        boolean isCursorPagination = cursor != null;
        int effectiveStartIndex;
        if (isCursorPagination) {
            effectiveStartIndex = ScimCursorCodec.decodeCursor(cursor, wsId) + 1;
        } else {
            effectiveStartIndex = (startIndex != null) ? startIndex : 1;
            if (effectiveStartIndex < 1) effectiveStartIndex = 1;
        }

        if (count < 0) count = 0;
        if (isCursorPagination && count > 200) {
            throw new ScimException(400, "tooMany", "Requested count exceeds maxPageSize (200)");
        }
        if (count > 200) count = 200; // Enforce maxResults from ServiceProviderConfig

        TargetResourceTypes targets = resolveTargetResourceTypes(filter);

        long totalUsers = 0;
        boolean usersEligible = targets.users;
        if (usersEligible) {
            try {
                totalUsers = ((Number) userService.listUsers(wsId, filter, null, "ascending", 1, 0)
                        .get("totalResults")).longValue();
            } catch (ScimException e) {
                if (isAttributeAbsenceError(e) && targets.groups) {
                    usersEligible = false;
                } else {
                    throw e;
                }
            }
        }

        long totalGroups = 0;
        boolean groupsEligible = targets.groups;
        if (groupsEligible) {
            try {
                totalGroups = ((Number) groupService.listGroups(wsId, filter, null, "ascending", 1, 0)
                        .get("totalResults")).longValue();
            } catch (ScimException e) {
                if (isAttributeAbsenceError(e) && targets.users) {
                    groupsEligible = false;
                } else {
                    throw e;
                }
            }
        }

        if (!usersEligible && !groupsEligible) {
            throw new ScimException(400, "invalidFilter", "Filter does not match any valid attribute: " + filter);
        }

        long totalResults = (usersEligible ? totalUsers : 0) + (groupsEligible ? totalGroups : 0);

        List<Map<String, Object>> allResources = new ArrayList<>();
        if (count > 0 && totalResults > 0) {
            if (usersEligible && !groupsEligible) {
                Map<String, Object> uResult = userService.listUsers(wsId, filter, sortBy, sortOrder, effectiveStartIndex, count);
                @SuppressWarnings("unchecked")
                List<ScimUser> users = (List<ScimUser>) uResult.get("Resources");
                allResources.addAll(mapUsers(users, baseUrl, compatBaseUrl, compatMode, attributes, excludedAttributes));
            } else if (!usersEligible && groupsEligible) {
                Map<String, Object> gResult = groupService.listGroups(wsId, filter, sortBy, sortOrder, effectiveStartIndex, count);
                @SuppressWarnings("unchecked")
                List<ScimGroup> groups = (List<ScimGroup>) gResult.get("Resources");
                allResources.addAll(mapGroups(groups, compatBaseUrl, attributes, excludedAttributes));
            } else {
                if (sortBy != null && !sortBy.isBlank()) {
                    int fetchLimit = (int) Math.min((long) effectiveStartIndex - 1 + count, totalResults);
                    List<Map<String, Object>> combined = new ArrayList<>();

                    if (totalUsers > 0) {
                        int userLimit = (int) Math.min((long) fetchLimit, totalUsers);
                        Map<String, Object> uResult = userService.listUsers(wsId, filter, sortBy, sortOrder, 1, userLimit);
                        @SuppressWarnings("unchecked")
                        List<ScimUser> users = (List<ScimUser>) uResult.get("Resources");
                        if (users != null && !users.isEmpty()) {
                            List<UUID> userIds = users.stream().map(ScimUser::getId).filter(Objects::nonNull).toList();
                            Map<UUID, List<Map<String, Object>>> groupsByUserId = userService.getUserGroupsBatch(userIds, baseUrl);
                            for (ScimUser u : users) {
                                List<Map<String, Object>> userGroups = groupsByUserId.getOrDefault(u.getId(), Collections.emptyList());
                                combined.add(ScimUserMapper.toScimResponse(u, compatBaseUrl, userGroups));
                            }
                        }
                    }

                    if (totalGroups > 0) {
                        int groupLimit = (int) Math.min((long) fetchLimit, totalGroups);
                        Map<String, Object> gResult = groupService.listGroups(wsId, filter, sortBy, sortOrder, 1, groupLimit);
                        @SuppressWarnings("unchecked")
                        List<ScimGroup> groups = (List<ScimGroup>) gResult.get("Resources");
                        if (groups != null && !groups.isEmpty()) {
                            for (ScimGroup g : groups) {
                                combined.add(ScimGroupMapper.toScimResponse(g, compatBaseUrl));
                            }
                        }
                    }

                    combined.sort(buildCrossResourceComparator(sortBy, sortOrder));

                    int sortOffset = Math.max(0, effectiveStartIndex - 1);
                    int toIndex = Math.min(sortOffset + count, combined.size());
                    List<Map<String, Object>> paged = (sortOffset < combined.size())
                            ? combined.subList(sortOffset, toIndex)
                            : Collections.emptyList();

                    for (Map<String, Object> res : paged) {
                        allResources.add(finalizeResource(res, compatMode, attributes, excludedAttributes));
                    }
                } else {
                    if (effectiveStartIndex <= totalUsers) {
                        int takeUsers = Math.min(count, (int) (totalUsers - effectiveStartIndex + 1));
                        if (takeUsers > 0) {
                            Map<String, Object> uResult = userService.listUsers(wsId, filter, sortBy, sortOrder, effectiveStartIndex, takeUsers);
                            @SuppressWarnings("unchecked")
                            List<ScimUser> users = (List<ScimUser>) uResult.get("Resources");
                            allResources.addAll(mapUsers(users, baseUrl, compatBaseUrl, compatMode, attributes, excludedAttributes));
                        }
                        int remaining = count - takeUsers;
                        if (remaining > 0 && totalGroups > 0) {
                            Map<String, Object> gResult = groupService.listGroups(wsId, filter, sortBy, sortOrder, 1, remaining);
                            @SuppressWarnings("unchecked")
                            List<ScimGroup> groups = (List<ScimGroup>) gResult.get("Resources");
                            allResources.addAll(mapGroups(groups, compatBaseUrl, attributes, excludedAttributes));
                        }
                    } else {
                        long groupStartIndex = effectiveStartIndex - totalUsers;
                        if (groupStartIndex <= totalGroups) {
                            Map<String, Object> gResult = groupService.listGroups(wsId, filter, sortBy, sortOrder, (int) groupStartIndex, count);
                            @SuppressWarnings("unchecked")
                            List<ScimGroup> groups = (List<ScimGroup>) gResult.get("Resources");
                            allResources.addAll(mapGroups(groups, compatBaseUrl, attributes, excludedAttributes));
                        }
                    }
                }
            }
        }

        return buildPaginatedListResponse(wsId, effectiveStartIndex, cursor, count, totalResults, allResources);
    }

    private List<Map<String, Object>> mapUsers(
            List<ScimUser> users,
            String baseUrl,
            String compatBaseUrl,
            CompatMode compatMode,
            String attributes,
            String excludedAttributes) {
        if (users == null || users.isEmpty()) {
            return Collections.emptyList();
        }
        List<UUID> userIds = users.stream().map(ScimUser::getId).filter(Objects::nonNull).toList();
        Map<UUID, List<Map<String, Object>>> groupsByUserId = userService.getUserGroupsBatch(userIds, baseUrl);

        return users.stream()
                .map(u -> {
                    List<Map<String, Object>> groups = groupsByUserId.getOrDefault(u.getId(), Collections.emptyList());
                    Map<String, Object> scimResp = ScimUserMapper.toScimResponse(u, compatBaseUrl, groups);
                    return finalizeResource(scimResp, compatMode, attributes, excludedAttributes);
                })
                .toList();
    }

    private List<Map<String, Object>> mapGroups(
            List<ScimGroup> groups,
            String compatBaseUrl,
            String attributes,
            String excludedAttributes) {
        if (groups == null || groups.isEmpty()) {
            return Collections.emptyList();
        }
        return groups.stream()
                .map(g -> {
                    Map<String, Object> scimResp = ScimGroupMapper.toScimResponse(g, compatBaseUrl);
                    return finalizeResource(scimResp, CompatMode.NONE, attributes, excludedAttributes);
                })
                .toList();
    }

    private Map<String, Object> finalizeResource(
            Map<String, Object> resource,
            CompatMode compatMode,
            String attributes,
            String excludedAttributes) {
        if (resource == null) {
            return null;
        }
        Map<?, ?> meta = (Map<?, ?>) resource.get("meta");
        boolean isUser = meta != null && "User".equalsIgnoreCase((String) meta.get("resourceType"));
        Map<String, Object> res = isUser ? applyCompat(resource, compatMode) : resource;
        if (!(res instanceof LinkedHashMap || res instanceof HashMap)) {
            res = new LinkedHashMap<>(res);
        }
        applyAttributeProjection(res, attributes, excludedAttributes);
        return res;
    }

    private Comparator<Map<String, Object>> buildCrossResourceComparator(String sortBy, String sortOrder) {
        boolean isDescending = "descending".equalsIgnoreCase(sortOrder);
        Comparator<String> strComp = ScimFilterParser.isSortByCaseExact(sortBy)
                ? Comparator.naturalOrder()
                : String.CASE_INSENSITIVE_ORDER;
        Comparator<String> valComparator = isDescending
                ? Comparator.nullsFirst(strComp.reversed())
                : Comparator.nullsLast(strComp);

        return (r1, r2) -> {
            String val1 = extractSortValue(r1, sortBy);
            String val2 = extractSortValue(r2, sortBy);
            int cmp = valComparator.compare(val1, val2);
            if (cmp != 0) {
                return cmp;
            }
            // Deterministic secondary tie-breaker by id
            String id1 = r1 != null && r1.get("id") != null ? r1.get("id").toString() : null;
            String id2 = r2 != null && r2.get("id") != null ? r2.get("id").toString() : null;
            if (id1 != null && id2 != null) {
                int idCmp = id1.compareTo(id2);
                return isDescending ? -idCmp : idCmp;
            } else if (id1 != null) {
                return -1;
            } else if (id2 != null) {
                return 1;
            }
            return 0;
        };
    }

    private String extractSortValue(Map<String, Object> resource, String sortBy) {
        if (resource == null || sortBy == null || sortBy.isBlank()) {
            return null;
        }

        String lower = sortBy.toLowerCase();
        String enterprisePrefixColon = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user:";
        String enterprisePrefixDot = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user.";
        String subAttr = null;
        if (lower.startsWith(enterprisePrefixColon)) {
            subAttr = sortBy.substring(enterprisePrefixColon.length());
        } else if (lower.startsWith(enterprisePrefixDot)) {
            subAttr = sortBy.substring(enterprisePrefixDot.length());
        }

        if (subAttr != null) {
            Object enterpriseObj = getCaseInsensitive(resource, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User");
            if (enterpriseObj instanceof Map<?, ?> enterpriseMap) {
                String[] parts = subAttr.split("\\.");
                Object current = enterpriseMap;
                for (String part : parts) {
                    if (!(current instanceof Map<?, ?> map)) {
                        return null;
                    }
                    current = getCaseInsensitive(map, part);
                    if (current == null) {
                        return null;
                    }
                }
                if (current instanceof Map || current instanceof Collection) {
                    return null;
                }
                return current.toString();
            }
            return null;
        }

        String stripped = sortBy;
        if (lower.startsWith("urn:ietf:params:scim:schemas:core:2.0:user:")) {
            stripped = sortBy.substring("urn:ietf:params:scim:schemas:core:2.0:user:".length());
        } else if (lower.startsWith("urn:ietf:params:scim:schemas:core:2.0:user.")) {
            stripped = sortBy.substring("urn:ietf:params:scim:schemas:core:2.0:user.".length());
        } else if (lower.startsWith("urn:ietf:params:scim:schemas:core:2.0:group:")) {
            stripped = sortBy.substring("urn:ietf:params:scim:schemas:core:2.0:group:".length());
        } else if (lower.startsWith("urn:ietf:params:scim:schemas:core:2.0:group.")) {
            stripped = sortBy.substring("urn:ietf:params:scim:schemas:core:2.0:group.".length());
        }

        String strippedLower = stripped.toLowerCase();
        if ("emails".equals(strippedLower) || "emails.value".equals(strippedLower)) {
            Object emailsObj = getCaseInsensitive(resource, "emails");
            if (emailsObj instanceof List<?> list && !list.isEmpty()) {
                for (Object item : list) {
                    if (item instanceof Map<?, ?> map) {
                        Object isPrimary = map.get("primary");
                        if (Boolean.TRUE.equals(isPrimary)) {
                            Object val = map.get("value");
                            if (val != null && !val.toString().isBlank()) {
                                return val.toString();
                            }
                        }
                    }
                }
                for (Object item : list) {
                    if (item instanceof Map<?, ?> map) {
                        Object val = map.get("value");
                        if (val != null && !val.toString().isBlank()) {
                            return val.toString();
                        }
                    }
                }
            }
            return null;
        }

        String[] parts = stripped.split("\\.");
        Object current = resource;
        for (String part : parts) {
            if (!(current instanceof Map<?, ?> map)) {
                return null;
            }
            current = getCaseInsensitive(map, part);
            if (current == null) {
                return null;
            }
        }
        if (current instanceof Map || current instanceof Collection) {
            return null;
        }
        return current.toString();
    }

    private static Object getCaseInsensitive(Map<?, ?> map, String key) {
        if (map == null || key == null) return null;
        Object val = map.get(key);
        if (val != null) return val;
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (entry.getKey() instanceof String k && k.equalsIgnoreCase(key)) {
                return entry.getValue();
            }
        }
        return null;
    }

    private Map<String, Object> applyCompat(Map<String, Object> scimResponse, CompatMode compatMode) {
        if (compatMode == CompatMode.MS) {
            Map<String, Object> copy = new LinkedHashMap<>(scimResponse);
            if (!copy.containsKey("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")) {
                copy.put("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", Collections.emptyMap());
            }
            return copy;
        }
        return scimResponse;
    }

    private ResponseEntity<Map<String, Object>> methodNotAllowed() {
        return methodNotAllowed("GET");
    }

    private ResponseEntity<Map<String, Object>> methodNotAllowed(String allowedMethods) {
        Map<String, Object> error = new LinkedHashMap<>();
        error.put(KEY_SCHEMAS, List.of("urn:ietf:params:scim:api:messages:2.0:Error"));
        error.put("status", "405");
        error.put("detail", "Method not allowed on discovery endpoint");
        return ResponseEntity.status(405)
                .header("Allow", allowedMethods)
                .contentType(SCIM_JSON)
                .body(error);
    }

}
