package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.compat.CompatMode;
import de.palsoftware.scim.server.impl.scim.mapper.MsScimUserMapper;
import de.palsoftware.scim.server.impl.scim.mapper.ScimUserMapper;
import de.palsoftware.scim.server.impl.service.ScimUserService;
import de.palsoftware.scim.server.impl.scim.model.ScimListResponse;
import de.palsoftware.scim.server.impl.scim.pagination.ScimCursorCodec;
import de.palsoftware.scim.server.impl.service.ScimAsyncEventService;
import de.palsoftware.scim.server.impl.scim.util.ScimPreferHeaderUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.Nullable;
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
    private final ScimAsyncEventService asyncEventService;

    public ScimUserController(ScimUserService userService) {
        this(userService, null);
    }

    @Autowired
    public ScimUserController(ScimUserService userService,
                              @Nullable ScimAsyncEventService asyncEventService) {
        this.userService = userService;
        this.asyncEventService = asyncEventService;
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

        if (asyncEventService != null && ScimPreferHeaderUtil.hasRespondAsync(request)) {
            UUID txnId = asyncEventService.submitAsync(wsId, "create", "User", null, compatBaseUrl, () -> {
                ScimUser user = userService.createUser(wsId, body);
                List<Map<String, Object>> groups = userService.getUserGroups(user.getId(), baseUrl);
                CompatMode compatMode = CompatMode.fromString(compat);
                Map<String, Object> scimResponse = ScimUserMapper.toScimResponse(user, compatBaseUrl, groups);
                return applyCompat(scimResponse, compatMode);
            });
            return buildAsyncAcceptedResponse(compatBaseUrl, txnId);
        }

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
            @RequestParam(required = false) Integer startIndex,
            @RequestParam(required = false, defaultValue = "100") int count,
            @RequestParam(required = false) String cursor,
            @RequestParam(required = false) String attributes,
            @RequestParam(required = false) String excludedAttributes,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        String baseUrl = buildBaseUrl(request, workspaceId);
        String compatBaseUrl = buildBaseUrl(request, workspaceId, compat);

        if (cursor != null && startIndex != null) {
            throw new ScimException(400, "invalidValue", "Cannot specify both cursor and startIndex");
        }

        boolean isCursorPagination = cursor != null;
        int offset;
        int effectiveStartIndex;
        if (isCursorPagination) {
            offset = ScimCursorCodec.decodeCursor(cursor, wsId);
            effectiveStartIndex = offset + 1;
        } else {
            effectiveStartIndex = (startIndex != null) ? startIndex : 1;
            if (effectiveStartIndex < 1) effectiveStartIndex = 1;
            offset = effectiveStartIndex - 1;
        }

        if (count < 0) count = 0;
        if (count > 200) count = 200; // Enforce maxResults from ServiceProviderConfig

        Map<String, Object> result = userService.listUsers(wsId, filter, sortBy, sortOrder, effectiveStartIndex, count);
        CompatMode compatMode = CompatMode.fromString(compat);

        List<ScimUser> users = result.get("Resources") instanceof List<?> list ? (List<ScimUser>) list : Collections.emptyList();

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

        Object totalObj = result.get("totalResults");
        long totalResults = totalObj instanceof Number num ? num.longValue() : resources.size();
        int itemsPerPage = resources.size();

        Map<String, Object> responseBody;
        if (isCursorPagination) {
            String previousCursor = null;
            if (offset > 0) {
                int prevOffset = Math.max(0, offset - count);
                previousCursor = ScimCursorCodec.encodeCursor(wsId, prevOffset);
            }
            String nextCursor = null;
            if ((long) offset + itemsPerPage < totalResults) {
                nextCursor = ScimCursorCodec.encodeCursor(wsId, offset + itemsPerPage);
            }
            responseBody = ScimListResponse.ofCursor(resources, totalResults, nextCursor, previousCursor).toMap();
        } else {
            responseBody = ScimListResponse.ofIndex(resources, totalResults, effectiveStartIndex).toMap();
        }

        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .body(responseBody);
    }

    public ResponseEntity<Map<String, Object>> listUsers(
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
        return listUsers(workspaceId, filter, sortBy, sortOrder, (Integer) startIndex, count, null,
                attributes, excludedAttributes, compat, request);
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

        if (asyncEventService != null && ScimPreferHeaderUtil.hasRespondAsync(request)) {
            UUID txnId = asyncEventService.submitAsync(wsId, "put", "User", uid, compatBaseUrl, () -> {
                ScimUser user = userService.replaceUser(wsId, uid, body, ifMatch);
                List<Map<String, Object>> groups = userService.getUserGroups(user.getId(), baseUrl);
                CompatMode compatMode = CompatMode.fromString(compat);
                Map<String, Object> scimResponse = ScimUserMapper.toScimResponse(user, compatBaseUrl, groups);
                return applyCompat(scimResponse, compatMode);
            });
            return buildAsyncAcceptedResponse(compatBaseUrl, txnId);
        }

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

        if (asyncEventService != null && ScimPreferHeaderUtil.hasRespondAsync(request)) {
            UUID txnId = asyncEventService.submitAsync(wsId, "patch", "User", uid, compatBaseUrl, () -> {
                ScimUser user = userService.patchUser(wsId, uid, operations, ifMatch);
                List<Map<String, Object>> groups = userService.getUserGroups(user.getId(), baseUrl);
                CompatMode compatMode = CompatMode.fromString(compat);
                Map<String, Object> scimResponse = ScimUserMapper.toScimResponse(user, compatBaseUrl, groups);
                return applyCompat(scimResponse, compatMode);
            });
            return buildAsyncAcceptedResponse(compatBaseUrl, txnId);
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

        String filter = null;
        Object filterObj = body.get("filter");
        if (filterObj instanceof String s) {
            filter = s;
        }

        String sortBy = "userName";
        Object sortByObj = body.get("sortBy");
        if (sortByObj instanceof String s && !s.isBlank()) {
            sortBy = s;
        }

        String sortOrder = "ascending";
        Object sortOrderObj = body.get("sortOrder");
        if (sortOrderObj instanceof String s && !s.isBlank()) {
            sortOrder = s;
        }

        String cursor = null;
        Object cursorObj = body.get("cursor");
        if (cursorObj instanceof String s) {
            cursor = s;
        }

        Integer startIndex = null;
        Object startIndexObj = body.get("startIndex");
        if (startIndexObj instanceof Number num) {
            startIndex = num.intValue();
        }

        if (cursor != null && startIndex != null) {
            throw new ScimException(400, "invalidValue", "Cannot specify both cursor and startIndex");
        }

        int count = 100;
        Object countObj = body.get("count");
        if (countObj instanceof Number num) {
            count = num.intValue();
        }

        String attributes = extractAttributesParam(body.get("attributes"));
        String excludedAttributes = extractAttributesParam(body.get("excludedAttributes"));

        return listUsers(workspaceId, filter, sortBy, sortOrder, startIndex, count, cursor,
                attributes, excludedAttributes, compat, request);
    }

    /**
     * DELETE /Users/{id} — Remove a user (RFC 7644 §3.6)
     */
    @DeleteMapping("/{userId}")
    public ResponseEntity<Void> deleteUser(
            @PathVariable String workspaceId,
            @PathVariable String userId,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        UUID uid = parseUUID(userId, "User");
        String compatBaseUrl = request != null ? buildBaseUrl(request, workspaceId, compat) : "";

        if (asyncEventService != null && request != null && ScimPreferHeaderUtil.hasRespondAsync(request)) {
            UUID txnId = asyncEventService.submitAsync(wsId, "delete", "User", uid, compatBaseUrl, () -> {
                userService.deleteUser(wsId, uid);
                return Collections.emptyMap();
            });
            return buildAsyncAcceptedResponse(compatBaseUrl, txnId);
        }

        userService.deleteUser(wsId, uid);

        return ResponseEntity.noContent().build();
    }

    public ResponseEntity<Void> deleteUser(
            String workspaceId,
            String userId,
            String compat) {
        return deleteUser(workspaceId, userId, compat, null);
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
