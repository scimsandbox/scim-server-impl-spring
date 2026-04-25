package de.palsoftware.scim.server.impl.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.model.WorkspaceToken;
import de.palsoftware.scim.server.impl.repository.WorkspaceTokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.*;

/**
 * Authenticates SCIM API requests using Bearer token.
 * Resolves workspace from URL path and validates token belongs to that workspace.
 */
public class BearerTokenAuthFilter extends OncePerRequestFilter {

    private final WorkspaceTokenRepository tokenRepository;
    private final ObjectMapper objectMapper;

    public BearerTokenAuthFilter(WorkspaceTokenRepository tokenRepository,
                                  ObjectMapper objectMapper) {
        this.tokenRepository = tokenRepository;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                     FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();

        // Only filter SCIM API paths: /ws/{workspaceId}/scim/v2/**
        if (!path.startsWith("/ws/") || !path.contains("/scim/v2")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extract workspace ID from path. SCIM routes accept UUID workspace IDs only.
        String[] segments = path.split("/");
        if (segments.length < 3) {
            sendScimError(response, 404, null, "Invalid workspace path");
            return;
        }

        String workspaceIdStr = segments[2]; // /ws/{workspaceId}/...
        UUID workspaceId;
        try {
            workspaceId = UUID.fromString(workspaceIdStr);
        } catch (IllegalArgumentException e) {
            sendScimError(response, 404, null, "Invalid workspace ID");
            return;
        }

        // Extract Bearer token
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            sendScimError(response, 401, null, "Missing or invalid Authorization header");
            return;
        }

        String token = authHeader.substring(7).trim();
        if (token.isEmpty()) {
            sendScimError(response, 401, null, "Empty bearer token");
            return;
        }

        // Validate token (hashed-at-rest only). JOIN FETCH loads workspace in one query.
        String tokenHash = TokenSecurityUtil.sha256Hex(token);
        Optional<WorkspaceToken> tokenOpt = tokenRepository.findByTokenHashAndNotRevoked(tokenHash);
        if (tokenOpt.isEmpty()) {
            sendScimError(response, 401, null, "Invalid or revoked token");
            return;
        }

        WorkspaceToken wsToken = tokenOpt.get();
        Workspace tokenWorkspace = wsToken.getWorkspace();

        // Check token belongs to this workspace
        if (!tokenWorkspace.getId().equals(workspaceId)) {
            sendScimError(response, 401, null, "Token does not belong to this workspace");
            return;
        }

        // Check expiry
        if (wsToken.getExpiresAt() != null && wsToken.getExpiresAt().isBefore(Instant.now())) {
            sendScimError(response, 401, null, "Token has expired");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void sendScimError(HttpServletResponse response, int status, String scimType, String detail)
            throws IOException {
        response.setStatus(status);
        response.setContentType("application/scim+json;charset=UTF-8");

        // RFC 7644 §3.12: 401 responses MUST include WWW-Authenticate header
        if (status == 401) {
            response.setHeader("WWW-Authenticate", "Bearer");
        }

        Map<String, Object> error = new LinkedHashMap<>();
        error.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:Error"));
        error.put("status", String.valueOf(status));
        if (scimType != null) error.put("scimType", scimType);
        error.put("detail", detail);

        response.getWriter().write(objectMapper.writeValueAsString(error));
    }
}
