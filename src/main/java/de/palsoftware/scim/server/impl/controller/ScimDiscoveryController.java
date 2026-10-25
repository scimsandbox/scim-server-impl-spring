package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.scim.compat.CompatMode;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.mapper.ScimGroupMapper;
import de.palsoftware.scim.server.impl.scim.mapper.ScimUserMapper;
import de.palsoftware.scim.server.impl.scim.schema.ScimSchemaDefinitions;
import de.palsoftware.scim.server.impl.service.ScimGroupService;
import de.palsoftware.scim.server.impl.service.ScimUserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
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

    private static final MediaType SCIM_JSON = MediaType.parseMediaType("application/scim+json");

    private final ScimUserService userService;
    private final ScimGroupService groupService;

    @Autowired
    public ScimDiscoveryController(ScimUserService userService, ScimGroupService groupService) {
        this.userService = userService;
        this.groupService = groupService;
    }

    public ScimDiscoveryController() {
        this(null, null);
    }

    // ─── ServiceProviderConfig ──────────────────────────────────────────

    @GetMapping("/ServiceProviderConfig")
        public ResponseEntity<Map<String, Object>> getServiceProviderConfig(
            @PathVariable(name = "compat", required = false) String compat) {
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
            @PathVariable(name = "compat", required = false) String compat) {
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
            @PathVariable(name = "compat", required = false) String compat) {
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
            @RequestParam(required = false, defaultValue = "1") int startIndex,
            @RequestParam(required = false, defaultValue = "100") int count,
            @RequestParam(required = false) String sortBy,
            @RequestParam(required = false, defaultValue = "ascending") String sortOrder,
            @RequestParam(required = false) String attributes,
            @RequestParam(required = false) String excludedAttributes,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        return executeRootSearch(workspaceId, filter, sortBy, sortOrder, startIndex, count,
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

        int startIndex = 1;
        Object startIndexObj = reqBody.get("startIndex");
        if (startIndexObj instanceof Number num) {
            startIndex = num.intValue();
        }

        int count = 100;
        Object countObj = reqBody.get("count");
        if (countObj instanceof Number num) {
            count = num.intValue();
        }

        String attributes = extractAttributesParam(reqBody.get("attributes"));
        String excludedAttributes = extractAttributesParam(reqBody.get("excludedAttributes"));

        return executeRootSearch(workspaceId, filter, sortBy, sortOrder, startIndex, count,
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
        return methodNotAllowed();
    }

    // ─── Helpers ────────────────────────────────────────────────────────

    private static final Pattern USER_TYPE_PATTERN = Pattern.compile(
            "(?i)\\b(?:urn:ietf:params:scim:schemas:core:2\\.0:(?:User|Group):)?meta\\.resourceType\\s+eq\\s+[\"']?User[\"']?"
    );
    private static final Pattern GROUP_TYPE_PATTERN = Pattern.compile(
            "(?i)\\b(?:urn:ietf:params:scim:schemas:core:2\\.0:(?:User|Group):)?meta\\.resourceType\\s+eq\\s+[\"']?Group[\"']?"
    );
    private static final Pattern NOT_USER_TYPE_PATTERN = Pattern.compile(
            "(?i)\\b(?:urn:ietf:params:scim:schemas:core:2\\.0:(?:User|Group):)?meta\\.resourceType\\s+ne\\s+[\"']?User[\"']?"
    );
    private static final Pattern NOT_GROUP_TYPE_PATTERN = Pattern.compile(
            "(?i)\\b(?:urn:ietf:params:scim:schemas:core:2\\.0:(?:User|Group):)?meta\\.resourceType\\s+ne\\s+[\"']?Group[\"']?"
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
        boolean hasUserEq = USER_TYPE_PATTERN.matcher(filter).find();
        boolean hasGroupEq = GROUP_TYPE_PATTERN.matcher(filter).find();
        boolean hasNotUser = NOT_USER_TYPE_PATTERN.matcher(filter).find();
        boolean hasNotGroup = NOT_GROUP_TYPE_PATTERN.matcher(filter).find();

        if (hasUserEq && hasGroupEq) {
            return new TargetResourceTypes(true, true);
        }
        if (hasUserEq || hasNotGroup) {
            return new TargetResourceTypes(true, false);
        }
        if (hasGroupEq || hasNotUser) {
            return new TargetResourceTypes(false, true);
        }
        return new TargetResourceTypes(true, true);
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
            int startIndex,
            int count,
            String attributes,
            String excludedAttributes,
            String compat,
            HttpServletRequest request) {

        if (compat != null && !compat.isBlank() && CompatMode.fromString(compat) == CompatMode.NONE) {
            throw new ScimException(404, null, "Resource or endpoint not found: " + compat);
        }

        if (userService == null || groupService == null) {
            throw new ScimException(500, null, "Services not initialized");
        }

        UUID wsId = resolveWorkspaceId(workspaceId);
        String baseUrl = buildBaseUrl(request, workspaceId);
        String compatBaseUrl = buildBaseUrl(request, workspaceId, compat);
        CompatMode compatMode = CompatMode.fromString(compat);

        if (startIndex < 1) startIndex = 1;
        if (count < 0) count = 0;
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
                Map<String, Object> uResult = userService.listUsers(wsId, filter, sortBy, sortOrder, startIndex, count);
                @SuppressWarnings("unchecked")
                List<ScimUser> users = (List<ScimUser>) uResult.get("Resources");
                allResources.addAll(mapUsers(users, baseUrl, compatBaseUrl, compatMode, attributes, excludedAttributes));
            } else if (!usersEligible && groupsEligible) {
                Map<String, Object> gResult = groupService.listGroups(wsId, filter, sortBy, sortOrder, startIndex, count);
                @SuppressWarnings("unchecked")
                List<ScimGroup> groups = (List<ScimGroup>) gResult.get("Resources");
                allResources.addAll(mapGroups(groups, compatBaseUrl, attributes, excludedAttributes));
            } else {
                if (startIndex <= totalUsers) {
                    int takeUsers = Math.min(count, (int) (totalUsers - startIndex + 1));
                    if (takeUsers > 0) {
                        Map<String, Object> uResult = userService.listUsers(wsId, filter, sortBy, sortOrder, startIndex, takeUsers);
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
                    long groupStartIndex = startIndex - totalUsers;
                    if (groupStartIndex <= totalGroups) {
                        Map<String, Object> gResult = groupService.listGroups(wsId, filter, sortBy, sortOrder, (int) groupStartIndex, count);
                        @SuppressWarnings("unchecked")
                        List<ScimGroup> groups = (List<ScimGroup>) gResult.get("Resources");
                        allResources.addAll(mapGroups(groups, compatBaseUrl, attributes, excludedAttributes));
                    }
                }
            }
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put(KEY_SCHEMAS, List.of("urn:ietf:params:scim:api:messages:2.0:ListResponse"));
        response.put("totalResults", totalResults);
        response.put("startIndex", startIndex);
        response.put("itemsPerPage", allResources.size());
        response.put("Resources", allResources);

        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .body(response);
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
        List<UUID> userIds = users.stream().map(ScimUser::getId).toList();
        Map<UUID, List<Map<String, Object>>> groupsByUserId = userService.getUserGroupsBatch(userIds, baseUrl);

        return users.stream()
                .map(u -> {
                    List<Map<String, Object>> groups = groupsByUserId.getOrDefault(u.getId(), Collections.emptyList());
                    Map<String, Object> scimResp = ScimUserMapper.toScimResponse(u, compatBaseUrl, groups);
                    scimResp = applyCompat(scimResp, compatMode);
                    applyAttributeProjection(scimResp, attributes, excludedAttributes);
                    return scimResp;
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
                    applyAttributeProjection(scimResp, attributes, excludedAttributes);
                    return scimResp;
                })
                .toList();
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
        Map<String, Object> error = new LinkedHashMap<>();
        error.put(KEY_SCHEMAS, List.of("urn:ietf:params:scim:api:messages:2.0:Error"));
        error.put("status", "405");
        error.put("detail", "Method not allowed on discovery endpoint");
        return ResponseEntity.status(405)
                .contentType(SCIM_JSON)
                .body(error);
    }

}
