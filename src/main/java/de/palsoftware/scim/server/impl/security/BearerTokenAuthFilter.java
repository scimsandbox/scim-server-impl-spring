package de.palsoftware.scim.server.impl.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.metrics.ScimRequestMetricAttributes;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.model.WorkspaceToken;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceTokenRepository;
import de.palsoftware.scim.server.impl.scim.compat.CompatMode;
import de.palsoftware.scim.server.impl.scim.error.ScimFilterErrorWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Authenticates SCIM API requests using Bearer token.
 * Resolves workspace from URL path and validates token belongs to that workspace.
 */
public class BearerTokenAuthFilter extends OncePerRequestFilter {

    /**
     * Request attribute populated ONLY after a valid, non-revoked, non-expired workspace
     * bearer token has been verified for the requested workspace UUID.
     */
    public static final String AUTHENTICATED_WORKSPACE_ID =
            BearerTokenAuthFilter.class.getName() + ".AUTHENTICATED_WORKSPACE_ID";

    private final WorkspaceTokenRepository tokenRepository;
    private final WorkspaceRepository workspaceRepository;
    private final ObjectMapper objectMapper;

    public BearerTokenAuthFilter(WorkspaceTokenRepository tokenRepository,
                                  ObjectMapper objectMapper) {
        this(tokenRepository, null, objectMapper);
    }

    public BearerTokenAuthFilter(WorkspaceTokenRepository tokenRepository,
                                  WorkspaceRepository workspaceRepository,
                                  ObjectMapper objectMapper) {
        this.tokenRepository = tokenRepository;
        this.workspaceRepository = workspaceRepository;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                     FilterChain filterChain) throws ServletException, IOException {
        request.removeAttribute(AUTHENTICATED_WORKSPACE_ID);
        String path = request.getRequestURI();

        // Only filter SCIM API paths: /ws/{workspaceId}/scim/v2/**
        if (!RequestPaths.isScimUri(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extract workspace ID from path. SCIM routes accept UUID workspace IDs only.
        UUID workspaceId = RequestPaths.extractWorkspaceId(path);
        if (workspaceId == null) {
            request.setAttribute(ScimRequestMetricAttributes.AUTHENTICATION, ScimRequestMetricAttributes.AUTH_FAILED);
            ScimFilterErrorWriter.writeScimError(response, objectMapper, 404, null, "Invalid workspace ID");
            return;
        }

        // Extract Bearer token
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null && "GET".equalsIgnoreCase(request.getMethod()) && isServiceProviderConfigEndpoint(path)) {
            if (workspaceRepository != null && !workspaceRepository.existsById(workspaceId)) {
                request.setAttribute(ScimRequestMetricAttributes.AUTHENTICATION, ScimRequestMetricAttributes.AUTH_FAILED);
                ScimFilterErrorWriter.writeScimError(response, objectMapper, 404, null, "Workspace not found");
                return;
            }
            request.setAttribute("WORKSPACE_ID", workspaceId.toString());
            request.setAttribute(ScimRequestMetricAttributes.AUTHENTICATION, ScimRequestMetricAttributes.AUTH_OK);
            filterChain.doFilter(request, response);
            return;
        }
        if (authHeader == null || !authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            request.setAttribute(ScimRequestMetricAttributes.AUTHENTICATION, ScimRequestMetricAttributes.AUTH_FAILED);
            ScimFilterErrorWriter.writeScimError(
                    response, objectMapper, 401, null, "Missing or invalid Authorization header");
            return;
        }

        String token = authHeader.substring(7).trim();
        if (token.isEmpty()) {
            request.setAttribute(ScimRequestMetricAttributes.AUTHENTICATION, ScimRequestMetricAttributes.AUTH_FAILED);
            ScimFilterErrorWriter.writeScimError(response, objectMapper, 401, null, "Empty bearer token");
            return;
        }

        // Validate token (hashed-at-rest only). JOIN FETCH loads workspace in one query.
        String tokenHash = TokenSecurityUtil.sha256Hex(token);
        Optional<WorkspaceToken> tokenOpt = tokenRepository.findByTokenHashAndNotRevoked(tokenHash);
        if (tokenOpt.isEmpty()) {
            request.setAttribute(ScimRequestMetricAttributes.AUTHENTICATION, ScimRequestMetricAttributes.AUTH_FAILED);
            ScimFilterErrorWriter.writeScimError(response, objectMapper, 401, null, "Invalid or revoked token");
            return;
        }

        WorkspaceToken wsToken = tokenOpt.get();
        Workspace tokenWorkspace = wsToken.getWorkspace();

        // Check token belongs to this workspace
        if (!tokenWorkspace.getId().equals(workspaceId)) {
            request.setAttribute(ScimRequestMetricAttributes.AUTHENTICATION, ScimRequestMetricAttributes.AUTH_FAILED);
            ScimFilterErrorWriter.writeScimError(
                    response, objectMapper, 401, null, "Token does not belong to this workspace");
            return;
        }

        // Check expiry
        if (wsToken.getExpiresAt() != null && wsToken.getExpiresAt().isBefore(Instant.now())) {
            request.setAttribute(ScimRequestMetricAttributes.AUTHENTICATION, ScimRequestMetricAttributes.AUTH_FAILED);
            ScimFilterErrorWriter.writeScimError(response, objectMapper, 401, null, "Token has expired");
            return;
        }

        request.setAttribute("USER_EMAIL", tokenWorkspace.getCreatedByUsername());
        request.setAttribute("WORKSPACE_ID", workspaceId.toString());
        request.setAttribute(AUTHENTICATED_WORKSPACE_ID, workspaceId);
        request.setAttribute(ScimRequestMetricAttributes.AUTHENTICATION, ScimRequestMetricAttributes.AUTH_OK);

        filterChain.doFilter(request, response);
    }

    private static boolean isServiceProviderConfigEndpoint(String path) {
        String normalized = (path.length() > 1 && path.endsWith("/"))
                ? path.substring(0, path.length() - 1)
                : path;
        String[] segments = normalized.split("/");
        // /ws/{workspaceId}/scim/v2/ServiceProviderConfig -> ["", "ws", "{uuid}", "scim", "v2", "ServiceProviderConfig"]
        if (segments.length == 6) {
            return "scim".equals(segments[3])
                    && "v2".equals(segments[4])
                    && "ServiceProviderConfig".equals(segments[5]);
        }
        // /ws/{workspaceId}/scim/v2/{compat}/ServiceProviderConfig
        if (segments.length == 7) {
            return "scim".equals(segments[3])
                    && "v2".equals(segments[4])
                    && CompatMode.fromString(segments[5]) != CompatMode.NONE
                    && "ServiceProviderConfig".equals(segments[6]);
        }
        return false;
    }
}
