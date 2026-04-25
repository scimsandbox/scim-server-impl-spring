package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.mapper.ScimGroupMapper;
import de.palsoftware.scim.server.impl.service.ScimGroupService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * SCIM 2.0 Groups endpoint per RFC 7644 §3.
 */
@RestController
@RequestMapping({"/ws/{workspaceId}/scim/v2/Groups", "/ws/{workspaceId}/scim/v2/{compat}/Groups"})
public class ScimGroupController extends ScimBaseController {

    private static final MediaType SCIM_JSON = MediaType.parseMediaType("application/scim+json");
    private static final String CONTENT_LOCATION_HEADER = "Content-Location";
    private static final String RESOURCE_GROUP = "Group";

    private final ScimGroupService groupService;

    public ScimGroupController(ScimGroupService groupService) {
        this.groupService = groupService;
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> createGroup(
            @PathVariable String workspaceId,
            @RequestBody Map<String, Object> body,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        String baseUrl = buildBaseUrl(request, workspaceId, compat);

        ScimGroup group = groupService.createGroup(wsId, body);
        Map<String, Object> scimResponse = ScimGroupMapper.toScimResponse(group, baseUrl);

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
            @RequestParam(required = false, defaultValue = "1") int startIndex,
            @RequestParam(required = false, defaultValue = "100") int count,
            @RequestParam(required = false) String attributes,
            @RequestParam(required = false) String excludedAttributes,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        String baseUrl = buildBaseUrl(request, workspaceId, compat);

        if (startIndex < 1) startIndex = 1;
        if (count < 0) count = 0;
        if (count > 200) count = 200; // Enforce maxResults from ServiceProviderConfig

        Map<String, Object> result = groupService.listGroups(wsId, filter, sortBy, sortOrder, startIndex, count);

        List<ScimGroup> groups = (List<ScimGroup>) result.get("Resources");
        List<Map<String, Object>> resources = groups.stream()
                .map(g -> {
                    Map<String, Object> scimResp = ScimGroupMapper.toScimResponse(g, baseUrl);
                    applyAttributeProjection(scimResp, attributes, excludedAttributes);
                    return scimResp;
                })
                .toList();
        result.put("Resources", resources);

        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .body(result);
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

        ScimGroup group = groupService.replaceGroup(wsId, gid, body, ifMatch);
        Map<String, Object> scimResponse = ScimGroupMapper.toScimResponse(group, baseUrl);

        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .header(CONTENT_LOCATION_HEADER, buildResourceUrl(baseUrl, group.getId()))
                .header("ETag", "W/\"" + group.getVersion() + "\"")
                .body(scimResponse);
    }

    @PatchMapping("/{groupId}")
    @SuppressWarnings("unchecked")
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

        List<String> schemas = (List<String>) body.get(KEY_SCHEMAS);
        if (schemas == null || !schemas.contains("urn:ietf:params:scim:api:messages:2.0:PatchOp")) {
            throw new ScimException(400, "invalidValue",
                    "PATCH request must include PatchOp schema");
        }

        List<Map<String, Object>> operations = (List<Map<String, Object>>) body.get("Operations");
        if (operations == null || operations.isEmpty()) {
            throw new ScimException(400, "invalidValue", "PATCH Operations is required");
        }

        ScimGroup group = groupService.patchGroup(wsId, gid, operations, ifMatch);
        Map<String, Object> scimResponse = ScimGroupMapper.toScimResponse(group, baseUrl);

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

        String filter = (String) body.get("filter");
        String sortBy = body.containsKey("sortBy") ? (String) body.get("sortBy") : "displayName";
        String sortOrder = body.containsKey("sortOrder") ? (String) body.get("sortOrder") : "ascending";
        int startIndex = body.containsKey("startIndex") ? ((Number) body.get("startIndex")).intValue() : 1;
        int count = body.containsKey("count") ? ((Number) body.get("count")).intValue() : 100;
        String attributes = (String) body.get("attributes");
        String excludedAttributes = (String) body.get("excludedAttributes");

        return listGroups(workspaceId, filter, sortBy, sortOrder, startIndex, count,
                attributes, excludedAttributes, compat, request);
    }

    @DeleteMapping("/{groupId}")
    public ResponseEntity<Void> deleteGroup(
            @PathVariable String workspaceId,
            @PathVariable String groupId,
            @PathVariable(name = "compat", required = false) String compat) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        UUID gid = parseUUID(groupId, RESOURCE_GROUP);
        groupService.deleteGroup(wsId, gid);

        return ResponseEntity.noContent().build();
    }

    private static String buildResourceUrl(String baseUrl, UUID groupId) {
        return baseUrl + "/" + RESOURCE_GROUP + "s/" + groupId;
    }

}
