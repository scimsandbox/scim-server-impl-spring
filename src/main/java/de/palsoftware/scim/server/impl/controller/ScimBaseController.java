package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.scim.error.ScimException;
import jakarta.servlet.http.HttpServletRequest;

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
        // Defense-in-depth: never return password (returned="never" per RFC 7643 §7)
        resource.remove("password");

        if (attributes != null && !attributes.isBlank()) {
            Set<String> requested = parseAttrList(attributes);
            requested.add(KEY_SCHEMAS);
            requested.add("id");
            requested.add("meta");
            resource.keySet().retainAll(requested);
        } else if (excludedAttributes != null && !excludedAttributes.isBlank()) {
            Set<String> excluded = parseAttrList(excludedAttributes);
            excluded.remove(KEY_SCHEMAS);
            excluded.remove("id");
            resource.keySet().removeAll(excluded);
        }
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
}
