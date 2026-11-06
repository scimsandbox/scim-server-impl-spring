package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.mapper.ScimGroupMapper;
import de.palsoftware.scim.server.impl.scim.pagination.ScimCursorCodec;
import de.palsoftware.scim.server.impl.service.ScimAsyncEventService;
import de.palsoftware.scim.server.impl.service.ScimGroupService;
import de.palsoftware.scim.server.impl.scim.util.ScimPreferHeaderUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * SCIM 2.0 Groups endpoint per RFC 7644 §3.
 */
@RestController
@RequestMapping({"/ws/{workspaceId}/scim/v2/Groups", "/ws/{workspaceId}/scim/v2/{compat}/Groups"})
public class ScimGroupController extends ScimBaseController {

    private static final String CONTENT_LOCATION_HEADER = "Content-Location";
    private static final String RESOURCE_GROUP = "Group";

    private final ScimGroupService groupService;
    private final ScimAsyncEventService asyncEventService;

    public ScimGroupController(ScimGroupService groupService,
                               ScimAsyncEventService asyncEventService) {
        this.groupService = groupService;
        this.asyncEventService = asyncEventService;
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> createGroup(
            @PathVariable String workspaceId,
            @RequestBody Map<String, Object> body,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        String baseUrl = buildBaseUrl(request, workspaceId, compat);

        if (ScimPreferHeaderUtil.shouldExecuteAsync(request)) {
            UUID txnId = asyncEventService.submitAsync(wsId, "POST", "Group", null, baseUrl, () -> {
                ScimGroup group = groupService.createGroup(wsId, body);
                return ScimGroupMapper.toScimResponse(group, baseUrl);
            });
            return buildAsyncAcceptedResponse(baseUrl, txnId, request);
        }

        ScimGroup group = groupService.createGroup(wsId, body);
        Map<String, Object> scimResponse = ScimGroupMapper.toScimResponse(group, baseUrl);
        if (request != null) {
            applyAttributeProjection(scimResponse, request.getParameter("attributes"), request.getParameter("excludedAttributes"));
        }

        String resourceUrl = buildResourceUrl(baseUrl, group.getId());
        return ResponseEntity.status(201)
                .contentType(SCIM_JSON)
                .header("Location", resourceUrl)
                .header(CONTENT_LOCATION_HEADER, resourceUrl)
                .header("ETag", "W/\"" + group.getVersion() + "\"")
                .body(scimResponse);
    }

    @GetMapping("/{groupId}")
    public ResponseEntity<Map<String, Object>> getGroup(
            @PathVariable String workspaceId,
            @PathVariable String groupId,
            @RequestParam(required = false) String attributes,
            @RequestParam(required = false) String excludedAttributes,
            @RequestHeader(value = "If-None-Match", required = false) String ifNoneMatch,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        UUID gid = parseUUID(groupId, RESOURCE_GROUP);
        String baseUrl = buildBaseUrl(request, workspaceId, compat);

        ScimGroup group = groupService.getGroup(wsId, gid);
        String etag = "W/\"" + group.getVersion() + "\"";

        // RFC 7644 §3.4.1: If-None-Match support
        if (ifNoneMatch != null && (ifNoneMatch.equals(etag) || ifNoneMatch.equals("*"))) {
            return ResponseEntity.status(304).eTag(etag).build();
        }

        Map<String, Object> scimResponse = ScimGroupMapper.toScimResponse(group, baseUrl);

        applyAttributeProjection(scimResponse, attributes, excludedAttributes);

        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .header(CONTENT_LOCATION_HEADER, buildResourceUrl(baseUrl, group.getId()))
                .header("ETag", etag)
                .body(scimResponse);
    }

    @GetMapping
    @SuppressWarnings("unchecked")
    public ResponseEntity<Map<String, Object>> listGroups(
            @PathVariable String workspaceId,
            @RequestParam(required = false) String filter,
            @RequestParam(required = false, defaultValue = "displayName") String sortBy,
            @RequestParam(required = false, defaultValue = "ascending") String sortOrder,
            @RequestParam(required = false) Integer startIndex,
            @RequestParam(required = false, defaultValue = "100") int count,
            @RequestParam(required = false) String cursor,
            @RequestParam(required = false) String attributes,
            @RequestParam(required = false) String excludedAttributes,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        String baseUrl = buildBaseUrl(request, workspaceId, compat);

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

        Map<String, Object> result = groupService.listGroups(wsId, filter, sortBy, sortOrder, effectiveStartIndex, count);

        List<ScimGroup> groups = result.get("Resources") instanceof List<?> list ? (List<ScimGroup>) list : Collections.emptyList();
        List<Map<String, Object>> resources = groups.stream()
                .map(g -> {
                    Map<String, Object> scimResp = ScimGroupMapper.toScimResponse(g, baseUrl);
                    applyAttributeProjection(scimResp, attributes, excludedAttributes);
                    return scimResp;
                })
                .toList();

        Object totalObj = result.get("totalResults");
        long totalResults = totalObj instanceof Number num ? num.longValue() : resources.size();

        return buildPaginatedListResponse(wsId, effectiveStartIndex, cursor, count, totalResults, resources);
    }

    @PutMapping("/{groupId}")
    public ResponseEntity<Map<String, Object>> replaceGroup(
            @PathVariable String workspaceId,
            @PathVariable String groupId,
            @RequestBody Map<String, Object> body,
            @RequestHeader(value = "If-Match", required = false) String ifMatch,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        UUID gid = parseUUID(groupId, RESOURCE_GROUP);
        
        String baseUrl = buildBaseUrl(request, workspaceId, compat);

        if (ScimPreferHeaderUtil.shouldExecuteAsync(request)) {
            UUID txnId = asyncEventService.submitAsync(wsId, "PUT", "Group", gid, baseUrl, () -> {
                ScimGroup group = groupService.replaceGroup(wsId, gid, body, ifMatch);
                return ScimGroupMapper.toScimResponse(group, baseUrl);
            });
            return buildAsyncAcceptedResponse(baseUrl, txnId, request);
        }

        ScimGroup group = groupService.replaceGroup(wsId, gid, body, ifMatch);
        Map<String, Object> scimResponse = ScimGroupMapper.toScimResponse(group, baseUrl);
        if (request != null) {
            applyAttributeProjection(scimResponse, request.getParameter("attributes"), request.getParameter("excludedAttributes"));
        }

        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .header(CONTENT_LOCATION_HEADER, buildResourceUrl(baseUrl, group.getId()))
                .header("ETag", "W/\"" + group.getVersion() + "\"")
                .body(scimResponse);
    }

    @PatchMapping("/{groupId}")
    public ResponseEntity<Map<String, Object>> patchGroup(
            @PathVariable String workspaceId,
            @PathVariable String groupId,
            @RequestBody Map<String, Object> body,
            @RequestHeader(value = "If-Match", required = false) String ifMatch,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        UUID gid = parseUUID(groupId, RESOURCE_GROUP);
        
        String baseUrl = buildBaseUrl(request, workspaceId, compat);

        List<Map<String, Object>> operations = extractAndValidatePatchOperations(body);

        if (ScimPreferHeaderUtil.shouldExecuteAsync(request)) {
            List<String> modifiedAttributes = extractModifiedPatchAttributes(operations);
            UUID txnId = asyncEventService.submitAsync(wsId, "PATCH", "Group", gid, baseUrl, () -> {
                ScimGroup group = groupService.patchGroup(wsId, gid, operations, ifMatch);
                Map<String, Object> out = new LinkedHashMap<>(ScimGroupMapper.toScimResponse(group, baseUrl));
                out.put(ScimAsyncEventService.INTERNAL_MODIFIED_ATTRIBUTES_KEY, modifiedAttributes);
                return out;
            });
            return buildAsyncAcceptedResponse(baseUrl, txnId, request);
        }

        ScimGroup group = groupService.patchGroup(wsId, gid, operations, ifMatch);
        Map<String, Object> scimResponse = ScimGroupMapper.toScimResponse(group, baseUrl);
        if (request != null) {
            applyAttributeProjection(scimResponse, request.getParameter("attributes"), request.getParameter("excludedAttributes"));
        }

        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .header(CONTENT_LOCATION_HEADER, buildResourceUrl(baseUrl, group.getId()))
                .header("ETag", "W/\"" + group.getVersion() + "\"")
                .body(scimResponse);
    }

    /**
     * POST /Groups/.search — Search groups via POST (RFC 7644 §3.4.3)
     */
    @PostMapping("/.search")
    public ResponseEntity<Map<String, Object>> searchGroups(
            @PathVariable String workspaceId,
            @RequestBody Map<String, Object> body,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        String filter = null;
        Object filterObj = body.get("filter");
        if (filterObj instanceof String s) {
            filter = s;
        }

        String sortBy = "displayName";
        Object sortByObj = body.get("sortBy");
        if (sortByObj instanceof String s && !s.isBlank()) {
            sortBy = s;
        }

        String sortOrder = "ascending";
        Object sortOrderObj = body.get("sortOrder");
        if (sortOrderObj instanceof String s && !s.isBlank()) {
            sortOrder = s;
        }

        String cursor = extractOptionalStringParam(body, "cursor");
        Integer startIndex = extractOptionalIntParam(body, "startIndex");

        if (cursor != null && startIndex != null) {
            throw new ScimException(400, "invalidValue", "Cannot specify both cursor and startIndex");
        }

        Integer countParam = extractOptionalIntParam(body, "count");
        int count = countParam != null ? countParam : 100;

        String attributes = extractAttributesParam(body.get("attributes"));
        String excludedAttributes = extractAttributesParam(body.get("excludedAttributes"));

        return listGroups(workspaceId, filter, sortBy, sortOrder, startIndex, count, cursor,
                attributes, excludedAttributes, compat, request);
    }

    @DeleteMapping("/{groupId}")
    public ResponseEntity<Void> deleteGroup(
            @PathVariable String workspaceId,
            @PathVariable String groupId,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        UUID gid = parseUUID(groupId, RESOURCE_GROUP);
        String baseUrl = request != null ? buildBaseUrl(request, workspaceId, compat) : "";
        String ifMatch = request != null ? request.getHeader("If-Match") : null;
        if (ifMatch != null && ifMatch.isBlank()) {
            ifMatch = null;
        }
        final String effectiveIfMatch = ifMatch;

        if (request != null && ScimPreferHeaderUtil.shouldExecuteAsync(request)) {
            UUID txnId = asyncEventService.submitAsync(wsId, "DELETE", "Group", gid, baseUrl, () -> {
                if (effectiveIfMatch != null) {
                    groupService.deleteGroup(wsId, gid, effectiveIfMatch);
                } else {
                    groupService.deleteGroup(wsId, gid);
                }
                return Collections.emptyMap();
            });
            return buildAsyncAcceptedResponse(baseUrl, txnId, request);
        }

        if (effectiveIfMatch != null) {
            groupService.deleteGroup(wsId, gid, effectiveIfMatch);
        } else {
            groupService.deleteGroup(wsId, gid);
        }

        return ResponseEntity.noContent().build();
    }

    private static String buildResourceUrl(String baseUrl, UUID groupId) {
        return baseUrl + "/" + RESOURCE_GROUP + "s/" + groupId;
    }

}
