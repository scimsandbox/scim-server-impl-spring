package de.palsoftware.scim.server.impl.security;

import jakarta.servlet.http.HttpServletRequest;

import java.util.UUID;

/**
 * Shared URI classification and workspace identifier extraction helpers for security and servlet filters.
 */
public final class RequestPaths {

    private static final String WORKSPACE_PREFIX = "/ws/";
    private static final String SCIM_V2_SEGMENT = "/scim/v2";
    private static final String SCIM_V2_PREFIX = "/scim/v2/";
    private static final int UUID_STRING_LENGTH = 36;

    private RequestPaths() {
    }

    public static boolean isActuatorPath(HttpServletRequest request) {
        return request != null && isActuatorUri(request.getRequestURI());
    }

    public static boolean isActuatorUri(String uri) {
        return uri != null && ("/actuator".equals(uri) || uri.startsWith("/actuator/"));
    }

    public static boolean isScimPath(HttpServletRequest request) {
        return request != null && isScimUri(request.getRequestURI());
    }

    public static boolean isScimUri(String uri) {
        return uri != null
                && uri.startsWith(WORKSPACE_PREFIX)
                && (uri.endsWith(SCIM_V2_SEGMENT) || uri.contains(SCIM_V2_PREFIX));
    }

    /**
     * Extracts the canonical UUID workspace identifier from {@code /ws/{workspaceId}/scim/v2...},
     * or returns {@code null} if the URI does not match or the workspace segment is not a 36-char UUID.
     */
    public static UUID extractWorkspaceId(String uri) {
        if (uri == null || !uri.startsWith(WORKSPACE_PREFIX)) {
            return null;
        }
        int nextSlash = uri.indexOf('/', WORKSPACE_PREFIX.length());
        if (nextSlash <= WORKSPACE_PREFIX.length()) {
            return null;
        }
        String rest = uri.substring(nextSlash);
        if (!SCIM_V2_SEGMENT.equals(rest) && !rest.startsWith(SCIM_V2_PREFIX)) {
            return null;
        }
        String candidate = uri.substring(WORKSPACE_PREFIX.length(), nextSlash);
        if (candidate.length() != UUID_STRING_LENGTH) {
            return null;
        }
        try {
            UUID parsed = UUID.fromString(candidate);
            return parsed.toString().equalsIgnoreCase(candidate) ? parsed : null;
        } catch (IllegalArgumentException _) {
            return null;
        }
    }
}
