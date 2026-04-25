package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.compat.CompatMode;
import de.palsoftware.scim.server.impl.scim.mapper.MsScimUserMapper;
import de.palsoftware.scim.server.impl.scim.mapper.ScimUserMapper;
import de.palsoftware.scim.server.impl.service.ScimUserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * SCIM 2.0 Users endpoint per RFC 7644 §3.
 * Supports: POST (Create), GET (Read/List), PUT (Replace), PATCH (Modify), DELETE.
 */
@RestController
@RequestMapping({"/ws/{workspaceId}/scim/v2/Users", "/ws/{workspaceId}/scim/v2/{compat}/Users"})
public class ScimUserController extends ScimBaseController {

    private static final MediaType SCIM_JSON = MediaType.parseMediaType("application/scim+json");
    private static final String CONTENT_LOCATION_HEADER = "Content-Location";
    private static final String RESOURCE_USER = "User";

    private final ScimUserService userService;

    public ScimUserController(ScimUserService userService) {
        this.userService = userService;
    }

    /**
     * POST /Users — Create a new user (RFC 7644 §3.3)
     */
    @PostMapping
    public ResponseEntity<Map<String, Object>> createUser(
            @PathVariable String workspaceId,
            @RequestBody Map<String, Object> body,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        String baseUrl = buildBaseUrl(request, workspaceId);
        String compatBaseUrl = buildBaseUrl(request, workspaceId, compat);

        ScimUser user = userService.createUser(wsId, body);
        List<Map<String, Object>> groups = userService.getUserGroups(user.getId(), baseUrl);
        CompatMode compatMode = CompatMode.fromString(compat);
        Map<String, Object> scimResponse = ScimUserMapper.toScimResponse(user, compatBaseUrl, groups);
        scimResponse = applyCompat(scimResponse, compatMode);

        String resourceUrl = buildResourceUrl(compatBaseUrl, user.getId());
        return ResponseEntity.status(201)
                .contentType(SCIM_JSON)
                .header("Location", resourceUrl)
                .header(CONTENT_LOCATION_HEADER, resourceUrl)
                .header("ETag", "W/\"" + user.getVersion() + "\"")
                .body(scimResponse);
    }

    /**
     * GET /Users/{id} — Read a specific user (RFC 7644 §3.4.1)
     */
    @GetMapping("/{userId}")
    public ResponseEntity<Map<String, Object>> getUser(
            @PathVariable String workspaceId,
            @PathVariable String userId,
            @RequestParam(required = false) String attributes,
            @RequestParam(required = false) String excludedAttributes,
            @RequestHeader(value = "If-None-Match", required = false) String ifNoneMatch,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        UUID uid = parseUUID(userId, "User");
        String baseUrl = buildBaseUrl(request, workspaceId);
        String compatBaseUrl = buildBaseUrl(request, workspaceId, compat);

        ScimUser user = userService.getUser(wsId, uid);
        String etag = "W/\"" + user.getVersion() + "\"";

        // RFC 7644 §3.4.1: If-None-Match support
        if (ifNoneMatch != null && (ifNoneMatch.equals(etag) || ifNoneMatch.equals("*"))) {
            return ResponseEntity.status(304).eTag(etag).build();
        }

        List<Map<String, Object>> groups = userService.getUserGroups(user.getId(), baseUrl);
        CompatMode compatMode = CompatMode.fromString(compat);
        Map<String, Object> scimResponse = ScimUserMapper.toScimResponse(user, compatBaseUrl, groups);
        scimResponse = applyCompat(scimResponse, compatMode);

        // Apply attribute projection
        applyAttributeProjection(scimResponse, attributes, excludedAttributes);

        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .header(CONTENT_LOCATION_HEADER, buildResourceUrl(compatBaseUrl, user.getId()))
                .header("ETag", etag)
                .body(scimResponse);
    }

    /**
     * GET /Users — List/filter users (RFC 7644 §3.4.2)
     */
    @GetMapping
    @SuppressWarnings("unchecked")
    public ResponseEntity<Map<String, Object>> listUsers(
            @PathVariable String workspaceId,
            @RequestParam(required = false) String filter,
            @RequestParam(required = false, defaultValue = "userName") String sortBy,
            @RequestParam(required = false, defaultValue = "ascending") String sortOrder,
            @RequestParam(required = false, defaultValue = "1") int startIndex,
            @RequestParam(required = false, defaultValue = "100") int count,
            @RequestParam(required = false) String attributes,
            @RequestParam(required = false) String excludedAttributes,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        String baseUrl = buildBaseUrl(request, workspaceId);
        String compatBaseUrl = buildBaseUrl(request, workspaceId, compat);

        if (startIndex < 1) startIndex = 1;
        if (count < 0) count = 0;
        if (count > 200) count = 200; // Enforce maxResults from ServiceProviderConfig

        Map<String, Object> result = userService.listUsers(wsId, filter, sortBy, sortOrder, startIndex, count);
        CompatMode compatMode = CompatMode.fromString(compat);

        // Convert ScimUser entities to SCIM response maps
        List<ScimUser> users = (List<ScimUser>) result.get("Resources");

        // Batch-load groups for all users in one query (avoids N+1)
        List<UUID> userIds = users.stream().map(ScimUser::getId).toList();
        Map<UUID, List<Map<String, Object>>> groupsByUserId = userService.getUserGroupsBatch(userIds, baseUrl);

        List<Map<String, Object>> resources = users.stream()
                .map(u -> {
                    List<Map<String, Object>> groups = groupsByUserId.getOrDefault(u.getId(), Collections.emptyList());
                    Map<String, Object> scimResp = ScimUserMapper.toScimResponse(u, compatBaseUrl, groups);
                    scimResp = applyCompat(scimResp, compatMode);
                    applyAttributeProjection(scimResp, attributes, excludedAttributes);
                    return scimResp;
                })
                .toList();
        result.put("Resources", resources);

        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .body(result);
    }

    /**
     * PUT /Users/{id} — Full replacement (RFC 7644 §3.5.1)
     */
    @PutMapping("/{userId}")
    public ResponseEntity<Map<String, Object>> replaceUser(
            @PathVariable String workspaceId,
            @PathVariable String userId,
            @RequestBody Map<String, Object> body,
            @RequestHeader(value = "If-Match", required = false) String ifMatch,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        UUID uid = parseUUID(userId, "User");
        
        String baseUrl = buildBaseUrl(request, workspaceId);
        String compatBaseUrl = buildBaseUrl(request, workspaceId, compat);
        ScimUser user = userService.replaceUser(wsId, uid, body, ifMatch);
        List<Map<String, Object>> groups = userService.getUserGroups(user.getId(), baseUrl);
        CompatMode compatMode = CompatMode.fromString(compat);
        Map<String, Object> scimResponse = ScimUserMapper.toScimResponse(user, compatBaseUrl, groups);
        scimResponse = applyCompat(scimResponse, compatMode);

        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .header(CONTENT_LOCATION_HEADER, buildResourceUrl(compatBaseUrl, user.getId()))
                .header("ETag", "W/\"" + user.getVersion() + "\"")
                .body(scimResponse);
    }

    /**
     * PATCH /Users/{id} — Partial modification (RFC 7644 §3.5.2)
     */
    @PatchMapping("/{userId}")
    @SuppressWarnings("unchecked")
    public ResponseEntity<Map<String, Object>> patchUser(
            @PathVariable String workspaceId,
            @PathVariable String userId,
            @RequestBody Map<String, Object> body,
            @RequestHeader(value = "If-Match", required = false) String ifMatch,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        UUID uid = parseUUID(userId, "User");
        
        String baseUrl = buildBaseUrl(request, workspaceId);
        String compatBaseUrl = buildBaseUrl(request, workspaceId, compat);

        // Validate PATCH schema
        List<String> schemas = (List<String>) body.get(KEY_SCHEMAS);
        if (schemas == null || !schemas.contains("urn:ietf:params:scim:api:messages:2.0:PatchOp")) {
            throw new ScimException(400, "invalidValue",
                    "PATCH request must include PatchOp schema");
        }

        List<Map<String, Object>> operations = (List<Map<String, Object>>) body.get("Operations");
        if (operations == null || operations.isEmpty()) {
            throw new ScimException(400, "invalidValue", "PATCH Operations is required");
        }

        ScimUser user = userService.patchUser(wsId, uid, operations, ifMatch);
        List<Map<String, Object>> groups = userService.getUserGroups(user.getId(), baseUrl);
        CompatMode compatMode = CompatMode.fromString(compat);
        Map<String, Object> scimResponse = ScimUserMapper.toScimResponse(user, compatBaseUrl, groups);
        scimResponse = applyCompat(scimResponse, compatMode);

        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .header(CONTENT_LOCATION_HEADER, buildResourceUrl(compatBaseUrl, user.getId()))
                .header("ETag", "W/\"" + user.getVersion() + "\"")
                .body(scimResponse);
    }

    /**
     * POST /Users/.search — Search users via POST (RFC 7644 §3.4.3)
     */
    @PostMapping("/.search")
    public ResponseEntity<Map<String, Object>> searchUsers(
            @PathVariable String workspaceId,
            @RequestBody Map<String, Object> body,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        String filter = (String) body.get("filter");
        String sortBy = body.containsKey("sortBy") ? (String) body.get("sortBy") : "userName";
        String sortOrder = body.containsKey("sortOrder") ? (String) body.get("sortOrder") : "ascending";
        int startIndex = body.containsKey("startIndex") ? ((Number) body.get("startIndex")).intValue() : 1;
        int count = body.containsKey("count") ? ((Number) body.get("count")).intValue() : 100;
        String attributes = (String) body.get("attributes");
        String excludedAttributes = (String) body.get("excludedAttributes");

        return listUsers(workspaceId, filter, sortBy, sortOrder, startIndex, count,
                attributes, excludedAttributes, compat, request);
    }

    /**
     * DELETE /Users/{id} — Remove a user (RFC 7644 §3.6)
     */
    @DeleteMapping("/{userId}")
    public ResponseEntity<Void> deleteUser(
            @PathVariable String workspaceId,
            @PathVariable String userId,
            @PathVariable(name = "compat", required = false) String compat) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        UUID uid = parseUUID(userId, "User");
        userService.deleteUser(wsId, uid);

        return ResponseEntity.noContent().build();
    }

    // ─── Helpers ────────────────────────────────────────────────────────

    private Map<String, Object> applyCompat(Map<String, Object> scimResponse, CompatMode compatMode) {
        if (compatMode == CompatMode.MS) {
            return MsScimUserMapper.toMsCompat(scimResponse);
        }
        return scimResponse;
    }

    private static String buildResourceUrl(String baseUrl, UUID userId) {
        return baseUrl + "/" + RESOURCE_USER + "s/" + userId;
    }
}
