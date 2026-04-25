package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.service.ScimGroupService;
import de.palsoftware.scim.server.impl.service.ScimUserService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * SCIM 2.0 Bulk Operations endpoint per RFC 7644 §3.7.
 */
@RestController
@RequestMapping({"/ws/{workspaceId}/scim/v2/Bulk", "/ws/{workspaceId}/scim/v2/{compat}/Bulk"})
public class ScimBulkController extends ScimBaseController {

    private static final Logger log = LoggerFactory.getLogger(ScimBulkController.class);

    private static final MediaType SCIM_JSON = MediaType.parseMediaType("application/scim+json");
    private static final String BULK_REQUEST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
    private static final int MAX_OPERATIONS = 1000;
    private static final int MAX_PAYLOAD_SIZE = 1048576; // 1 MB per ServiceProviderConfig
    private static final String KEY_FAIL_ON_ERRORS = "failOnErrors";
    private static final String KEY_OPERATIONS = "Operations";
    private static final String KEY_STATUS = "status";
    private static final String KEY_RESPONSE = "response";
    private static final String KEY_LOCATION = "location";
    private static final String RESOURCE_USERS = "Users";
    private static final String RESOURCE_GROUPS = "Groups";

    private final ScimUserService userService;
    private final ScimGroupService groupService;

    public ScimBulkController(ScimUserService userService, ScimGroupService groupService) {
        this.userService = userService;
        this.groupService = groupService;
    }

    @PostMapping
    @SuppressWarnings("unchecked")
    public ResponseEntity<Map<String, Object>> processBulk(
            @PathVariable String workspaceId,
            @RequestBody Map<String, Object> body,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        String baseUrl = buildBaseUrl(request, workspaceId, compat);

        validateBulkRequest(request, body);

        List<Map<String, Object>> operations = (List<Map<String, Object>>) body.get(KEY_OPERATIONS);
        int failOnErrors = parseFailOnErrors(body.get(KEY_FAIL_ON_ERRORS));

        // Process bulkId references — map bulkId → created resource ID
        Map<String, String> bulkIdMap = new LinkedHashMap<>();
        List<Map<String, Object>> results = new ArrayList<>();
        int errorCount = 0;

        for (Map<String, Object> op : operations) {
            Map<String, Object> result = processOperation(op, wsId, baseUrl, bulkIdMap);
            results.add(result);

            if (isErrorResult(result)) {
                errorCount++;
                if (shouldStopProcessing(failOnErrors, errorCount)) {
                    break;
                }
            }
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkResponse"));
        response.put(KEY_OPERATIONS, results);

        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .body(response);
    }

    @SuppressWarnings("unchecked")
    private static void validateBulkRequest(HttpServletRequest request, Map<String, Object> body) {
        long contentLength = request.getContentLengthLong();
        if (contentLength > MAX_PAYLOAD_SIZE) {
            throw new ScimException(413, null,
                    "Bulk request exceeds maxPayloadSize (" + MAX_PAYLOAD_SIZE + " bytes)");
        }

        List<String> schemas = (List<String>) body.get(KEY_SCHEMAS);
        if (schemas == null || !schemas.contains(BULK_REQUEST_SCHEMA)) {
            throw new ScimException(400, "invalidValue", "Bulk request must include BulkRequest schema");
        }

        List<Map<String, Object>> operations = (List<Map<String, Object>>) body.get(KEY_OPERATIONS);
        if (operations == null) {
            throw new ScimException(400, "invalidValue", "Bulk request must contain Operations");
        }
        if (operations.size() > MAX_OPERATIONS) {
            throw new ScimException(413, null,
                    "Bulk request exceeds maxOperations (" + MAX_OPERATIONS + ")");
        }
    }

    private static int parseFailOnErrors(Object failOnErrorsObj) {
        if (failOnErrorsObj instanceof Number number) {
            return number.intValue();
        }
        return 0;
    }

    private static boolean isErrorResult(Map<String, Object> result) {
        String status = (String) result.get(KEY_STATUS);
        if (status == null) {
            return false;
        }
        try {
            return Integer.parseInt(status) >= 400;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static boolean shouldStopProcessing(int failOnErrors, int errorCount) {
        return failOnErrors > 0 && errorCount >= failOnErrors;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> processOperation(Map<String, Object> op, UUID wsId,
                                                   String baseUrl, Map<String, String> bulkIdMap) {
        Object rawMethod = op.get("method");
        if (!(rawMethod instanceof String)) {
            throw new ScimException(400, "invalidValue", "Operation method is required");
        }
        String method = ((String) rawMethod).toUpperCase();
        String path = (String) op.get("path");
        String bulkId = (String) op.get("bulkId");
        Map<String, Object> data = (Map<String, Object>) op.get("data");

        Map<String, Object> result = new LinkedHashMap<>();
        if (bulkId != null) result.put("bulkId", bulkId);
        result.put("method", method);

        try {
            // Resolve bulkId references in path
            if (path != null) {
                path = resolveBulkIdReferences(path, bulkIdMap);
            }

            // Resolve bulkId references in data
            if (data != null) {
                data = resolveBulkIdInData(data, bulkIdMap);
            }

            switch (method) {
                case "POST":
                    result.putAll(handlePost(path, data, wsId, baseUrl, bulkId, bulkIdMap));
                    break;
                case "PUT":
                    result.putAll(handlePut(path, data, wsId, baseUrl));
                    break;
                case "PATCH":
                    result.putAll(handlePatch(path, data, wsId, baseUrl));
                    break;
                case "DELETE":
                    result.putAll(handleDelete(path, wsId));
                    break;
                default:
                    result.put(KEY_STATUS, "400");
                    result.put(KEY_RESPONSE, buildError("400", "invalidValue", "Unsupported method: " + method));
            }
        } catch (ScimException e) {
            result.put(KEY_STATUS, String.valueOf(e.getHttpStatus()));
            result.put(KEY_RESPONSE, buildError(
                    String.valueOf(e.getHttpStatus()), e.getScimType(), e.getMessage()));
        } catch (Exception e) {
            log.error("Unhandled bulk operation failure for method={}, path={}, bulkId={}", method, path, bulkId, e);
            result.put(KEY_STATUS, "500");
            result.put(KEY_RESPONSE, buildError("500", null, "Internal server error"));
        }

        return result;
    }

    private Map<String, Object> handlePost(String path, Map<String, Object> data, UUID wsId,
                                            String baseUrl, String bulkId, Map<String, String> bulkIdMap) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (path.startsWith("/" + RESOURCE_USERS)) {
            ScimUser user = userService.createUser(wsId, data);
            result.put(KEY_STATUS, "201");
            result.put(KEY_LOCATION, buildResourceLocation(baseUrl, RESOURCE_USERS, user.getId()));
            if (bulkId != null) {
                bulkIdMap.put(bulkId, user.getId().toString());
            }
        } else if (path.startsWith("/" + RESOURCE_GROUPS)) {
            ScimGroup group = groupService.createGroup(wsId, data);
            result.put(KEY_STATUS, "201");
            result.put(KEY_LOCATION, buildResourceLocation(baseUrl, RESOURCE_GROUPS, group.getId()));
            if (bulkId != null) {
                bulkIdMap.put(bulkId, group.getId().toString());
            }
        } else {
            throw new ScimException(400, "invalidValue", "Unknown resource path: " + path);
        }
        return result;
    }

    private Map<String, Object> handlePut(String path, Map<String, Object> data, UUID wsId, String baseUrl) {
        Map<String, Object> result = new LinkedHashMap<>();
        String[] parts = parsePath(path);
        String resourceType = parts[0];
        UUID resourceId = UUID.fromString(parts[1]);

        if (RESOURCE_USERS.equals(resourceType)) {
            ScimUser user = userService.replaceUser(wsId, resourceId, data, null);
            result.put(KEY_STATUS, "200");
            result.put(KEY_LOCATION, buildResourceLocation(baseUrl, RESOURCE_USERS, user.getId()));
        } else if (RESOURCE_GROUPS.equals(resourceType)) {
            ScimGroup group = groupService.replaceGroup(wsId, resourceId, data, null);
            result.put(KEY_STATUS, "200");
            result.put(KEY_LOCATION, buildResourceLocation(baseUrl, RESOURCE_GROUPS, group.getId()));
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> handlePatch(String path, Map<String, Object> data, UUID wsId, String baseUrl) {
        Map<String, Object> result = new LinkedHashMap<>();
        String[] parts = parsePath(path);
        String resourceType = parts[0];
        UUID resourceId = UUID.fromString(parts[1]);

        List<Map<String, Object>> operations = (List<Map<String, Object>>) data.get(KEY_OPERATIONS);
        if (operations == null) operations = List.of();

        if (RESOURCE_USERS.equals(resourceType)) {
            ScimUser user = userService.patchUser(wsId, resourceId, operations, null);
            result.put(KEY_STATUS, "200");
            result.put(KEY_LOCATION, buildResourceLocation(baseUrl, RESOURCE_USERS, user.getId()));
        } else if (RESOURCE_GROUPS.equals(resourceType)) {
            ScimGroup group = groupService.patchGroup(wsId, resourceId, operations, null);
            result.put(KEY_STATUS, "200");
            result.put(KEY_LOCATION, buildResourceLocation(baseUrl, RESOURCE_GROUPS, group.getId()));
        }
        return result;
    }

    private Map<String, Object> handleDelete(String path, UUID wsId) {
        Map<String, Object> result = new LinkedHashMap<>();
        String[] parts = parsePath(path);
        String resourceType = parts[0];
        UUID resourceId = UUID.fromString(parts[1]);

        if (RESOURCE_USERS.equals(resourceType)) {
            userService.deleteUser(wsId, resourceId);
        } else if (RESOURCE_GROUPS.equals(resourceType)) {
            groupService.deleteGroup(wsId, resourceId);
        }
        result.put(KEY_STATUS, "204");
        return result;
    }

    private String[] parsePath(String path) {
        // path like /Users/uuid or /Groups/uuid
        String cleaned = path.startsWith("/") ? path.substring(1) : path;
        String[] parts = cleaned.split("/", 2);
        if (parts.length < 2) {
            throw new ScimException(400, "invalidPath", "Bulk path must include resource ID: " + path);
        }
        return parts;
    }

    private String resolveBulkIdReferences(String path, Map<String, String> bulkIdMap) {
        for (Map.Entry<String, String> entry : bulkIdMap.entrySet()) {
            path = path.replace("bulkId:" + entry.getKey(), entry.getValue());
        }
        return path;
    }

    private Map<String, Object> resolveBulkIdInData(Map<String, Object> data, Map<String, String> bulkIdMap) {
        Map<String, Object> resolved = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            resolved.put(entry.getKey(), resolveValue(entry.getValue(), bulkIdMap));
        }
        return resolved;
    }

    @SuppressWarnings("unchecked")
    private Object resolveValue(Object value, Map<String, String> bulkIdMap) {
        if (value instanceof String s) {
            return resolveString(s, bulkIdMap);
        } else if (value instanceof Map) {
            return resolveBulkIdInData((Map<String, Object>) value, bulkIdMap);
        } else if (value instanceof List) {
            return resolveList((List<Object>) value, bulkIdMap);
        } else {
            return value;
        }
    }

    private String resolveString(String s, Map<String, String> bulkIdMap) {
        if (s.startsWith("bulkId:")) {
            String ref = s.substring(7);
            return bulkIdMap.getOrDefault(ref, s);
        }
        return s;
    }

    private List<Object> resolveList(List<Object> list, Map<String, String> bulkIdMap) {
        List<Object> resolvedList = new ArrayList<>(list.size());
        for (Object item : list) {
            resolvedList.add(resolveValue(item, bulkIdMap));
        }
        return resolvedList;
    }

    private Map<String, Object> buildError(String status, String scimType, String detail) {
        Map<String, Object> error = new LinkedHashMap<>();
        error.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:Error"));
        error.put(KEY_STATUS, status);
        if (scimType != null) error.put("scimType", scimType);
        if (detail != null) error.put("detail", detail);
        return error;
    }

    private String buildResourceLocation(String baseUrl, String resourceType, UUID resourceId) {
        return baseUrl + "/" + resourceType + "/" + resourceId;
    }
}
