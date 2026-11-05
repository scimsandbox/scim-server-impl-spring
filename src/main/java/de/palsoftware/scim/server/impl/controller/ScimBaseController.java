package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.projection.ScimAttributeProjector;
import de.palsoftware.scim.server.impl.scim.util.ScimPreferHeaderUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.*;
import java.util.stream.Collectors;

abstract class ScimBaseController {

    protected ScimBaseController() {
    }

    protected static final String KEY_SCHEMAS = "schemas";

    protected static UUID resolveWorkspaceId(String workspaceId) {
        try {
            return UUID.fromString(workspaceId);
        } catch (IllegalArgumentException e) {
            throw new ScimException(404, null, "Invalid workspace ID: " + workspaceId, e);
        }
    }

    protected static UUID parseUUID(String value, String resourceType) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException e) {
            throw new ScimException(404, null, resourceType + " not found: " + value, e);
        }
    }

    protected static String buildBaseUrl(HttpServletRequest request, String workspaceId) {
        return buildBaseUrl(request, workspaceId, null);
    }

    protected static String buildBaseUrl(HttpServletRequest request, String workspaceId, String compat) {
        // Only the scheme is taken from a forwarded header: the edge terminates TLS and reaches this
        // service over plain http, and it overwrites X-Forwarded-Proto itself. X-Forwarded-Host and
        // X-Forwarded-Port are deliberately NOT read - any client can send them, and they would become
        // the authority in every meta.location and $ref handed back. Host is authoritative because the
        // proxy routes on it.
        String forwardedProto = request.getHeader("X-Forwarded-Proto");
        String scheme = forwardedProto != null
                ? sanitizeHeaderValue(forwardedProto.split(",")[0].trim())
                : request.getScheme();

        String host = request.getServerName();
        if (host == null || host.isBlank()) {
            host = "localhost";
        }

        int port = request.getServerPort();

        String portStr = shouldAppendPort(port, host) ? ":" + port : "";
        String base = scheme + "://" + host + portStr + "/ws/" + workspaceId + "/scim/v2";
        if (compat != null && !compat.isBlank()) {
            return base + "/" + compat;
        }
        return base;
    }

    private static boolean shouldAppendPort(int port, String host) {
        return port != 80 && port != 443 && !host.contains(":");
    }

    private static String sanitizeHeaderValue(String value) {
        // Reject header values containing newlines (header injection) or non-printable characters
        if (value == null) return null;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                throw new ScimException(400, "invalidValue", "Invalid header value");
            }
        }
        return value;
    }

    protected static void applyAttributeProjection(Map<String, Object> resource,
                                                    String attributes, String excludedAttributes) {
        ScimAttributeProjector.applyProjection(resource, attributes, excludedAttributes);
    }

    @SuppressWarnings("unchecked")
    protected static List<Map<String, Object>> extractAndValidatePatchOperations(Map<String, Object> body) {
        if (body == null) {
            throw new ScimException(400, "invalidSyntax", "PATCH request body is required");
        }
        Object rawSchemas = body.get(KEY_SCHEMAS);
        if (!(rawSchemas instanceof List<?> schemaList)
                || !schemaList.contains("urn:ietf:params:scim:api:messages:2.0:PatchOp")) {
            throw new ScimException(400, "invalidValue", "PATCH request must include PatchOp schema");
        }

        Object rawOps = body.get("Operations");
        if (rawOps == null) {
            for (Map.Entry<String, Object> entry : body.entrySet()) {
                if ("operations".equalsIgnoreCase(entry.getKey())) {
                    rawOps = entry.getValue();
                    break;
                }
            }
        }
        if (!(rawOps instanceof List<?> list) || list.isEmpty()) {
            throw new ScimException(400, "invalidSyntax", "PATCH Operations must be a non-empty array");
        }

        List<Map<String, Object>> operations = new ArrayList<>(list.size());
        for (Object elem : list) {
            if (!(elem instanceof Map<?, ?> opMap)) {
                throw new ScimException(400, "invalidSyntax", "Each PATCH operation must be a JSON object");
            }
            Object opField = opMap.get("op");
            if (!(opField instanceof String s) || s.isBlank()) {
                throw new ScimException(400, "invalidValue", "Each PATCH operation must include a non-empty string 'op'");
            }
            operations.add((Map<String, Object>) opMap);
        }
        return operations;
    }

    protected static List<String> extractModifiedPatchAttributes(List<Map<String, Object>> operations) {
        if (operations == null || operations.isEmpty()) {
            return Collections.emptyList();
        }
        Set<String> attrs = new LinkedHashSet<>();
        for (Map<String, Object> op : operations) {
            Object rawPath = op.get("path");
            if (rawPath instanceof String p && !p.isBlank()) {
                // Normalize filtered valuePath 'emails[type eq "work"].value' -> 'emails.value'
                String cleaned = stripBracketFilters(p.trim());
                if (!cleaned.isEmpty()) {
                    attrs.add(cleaned);
                }
            } else if (op.get("value") instanceof Map<?, ?> valMap) {
                for (Map.Entry<?, ?> entry : valMap.entrySet()) {
                    if (entry.getKey() instanceof String k && !k.isBlank()
                            && !"schemas".equalsIgnoreCase(k)
                            && !"id".equalsIgnoreCase(k)
                            && !"meta".equalsIgnoreCase(k)) {
                        String trimmedKey = k.trim();
                        if ("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User".equalsIgnoreCase(trimmedKey)
                                && entry.getValue() instanceof Map<?, ?> extMap && !extMap.isEmpty()) {
                            for (Object subK : extMap.keySet()) {
                                if (subK instanceof String subStr && !subStr.isBlank()) {
                                    attrs.add(trimmedKey + ":" + subStr.trim());
                                }
                            }
                        } else {
                            attrs.add(trimmedKey);
                        }
                    }
                }
            }
        }
        return new ArrayList<>(attrs);
    }

    /**
     * Strips bracketed valuePath filter segments (e.g. {@code emails[type eq "work"].value -> emails.value})
     * in linear O(n) time without regular expressions to avoid polynomial backtracking on unclosed brackets.
     */
    static String stripBracketFilters(String path) {
        if (path == null) {
            return "";
        }
        int firstOpen = path.indexOf('[');
        if (firstOpen < 0) {
            return path;
        }
        int len = path.length();
        StringBuilder sb = new StringBuilder(len);
        int cursor = 0;
        int openIdx = firstOpen;
        while (openIdx >= 0) {
            sb.append(path, cursor, openIdx);
            int closeIdx = path.indexOf(']', openIdx + 1);
            if (closeIdx < 0) {
                sb.append(path, openIdx, len);
                return sb.toString();
            }
            cursor = closeIdx + 1;
            openIdx = path.indexOf('[', cursor);
        }
        if (cursor < len) {
            sb.append(path, cursor, len);
        }
        return sb.toString();
    }

    protected static Set<String> parseAttrList(String attrList) {
        Set<String> result = new LinkedHashSet<>();
        for (String attr : attrList.split(",")) {
            String trimmed = attr.trim();
            if (!trimmed.isEmpty()) {
                result.add(resolveUrnPrefixedAttribute(trimmed));
            }
        }
        return result;
    }

    /**
     * Resolves URN-prefixed attribute names to their top-level map keys.
     * For example:
     * - "urn:ietf:params:scim:schemas:core:2.0:User:userName" → "userName"
     * - "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber" → "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
     *   (the entire enterprise extension is a top-level key; sub-attribute requests return the whole extension)
     * - "userName" → "userName" (no transformation)
     */
    private static String resolveUrnPrefixedAttribute(String attr) {
        if (!attr.startsWith("urn:")) {
            return attr;
        }
        // Enterprise extension URN — the extension itself is a top-level key
        String enterpriseUrn = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
        if (attr.startsWith(enterpriseUrn)) {
            return enterpriseUrn;
        }
        // Core schema URN prefix: "urn:ietf:params:scim:schemas:core:2.0:User:" or "...Group:"
        String userCorePrefix = "urn:ietf:params:scim:schemas:core:2.0:User:";
        if (attr.startsWith(userCorePrefix)) {
            return attr.substring(userCorePrefix.length());
        }
        String groupCorePrefix = "urn:ietf:params:scim:schemas:core:2.0:Group:";
        if (attr.startsWith(groupCorePrefix)) {
            return attr.substring(groupCorePrefix.length());
        }
        // Unknown URN — return as-is
        return attr;
    }

    /**
     * Extracts an attributes or excludedAttributes parameter from a SearchRequest payload,
     * which can be formatted either as a JSON Array of strings (per RFC 7644 §3.4.3) or
     * as a comma-separated String.
     */
    protected static String extractAttributesParam(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof List<?> list) {
            return list.stream()
                    .map(Object::toString)
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .collect(Collectors.joining(","));
        }
        if (value instanceof String str) {
            return str.isBlank() ? null : str.trim();
        }
        return value.toString().trim();
    }

    protected static Integer extractOptionalIntParam(Map<String, Object> body, String key) {
        if (body == null || !body.containsKey(key) || body.get(key) == null) {
            return null;
        }
        Object raw = body.get(key);
        if (raw instanceof Integer i) {
            return i;
        }
        if (raw instanceof Long l) {
            return l.intValue();
        }
        if (raw instanceof Short s) {
            return (int) s;
        }
        throw new ScimException(400, "invalidValue", "Parameter '" + key + "' must be an integer");
    }

    protected static String extractOptionalStringParam(Map<String, Object> body, String key) {
        if (body == null || !body.containsKey(key) || body.get(key) == null) {
            return null;
        }
        Object raw = body.get(key);
        if (raw instanceof String s) {
            return s;
        }
        throw new ScimException(400, "invalidValue", "Parameter '" + key + "' must be a string");
    }

    protected static <T> ResponseEntity<T> buildAsyncAcceptedResponse(String baseUrl, UUID txnId) {
        return buildAsyncAcceptedResponse(baseUrl, txnId, null);
    }

    protected static <T> ResponseEntity<T> buildAsyncAcceptedResponse(String baseUrl, UUID txnId, HttpServletRequest request) {
        String location = baseUrl + "/Events/" + txnId;
        String preferenceApplied = ScimPreferHeaderUtil.buildPreferenceAppliedHeader(request);
        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .header(ScimPreferHeaderUtil.SET_TXN_HEADER, txnId.toString())
                .header(ScimPreferHeaderUtil.PREFERENCE_APPLIED_HEADER, preferenceApplied)
                .header("Location", location)
                .build();
    }
}
