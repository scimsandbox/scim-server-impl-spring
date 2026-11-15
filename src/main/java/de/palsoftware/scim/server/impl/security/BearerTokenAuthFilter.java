package de.palsoftware.scim.server.impl.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.filter.ThrottlingFilter;
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
import org.springframework.http.HttpStatus;
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

    static final int MAX_BEARER_TOKEN_LENGTH = 512;
    private static final String INVALID_OR_REVOKED_TOKEN_DETAIL = "Invalid or revoked token";

    private final WorkspaceTokenRepository tokenRepository;
    private final WorkspaceRepository workspaceRepository;
    private final ObjectMapper objectMapper;
    private final ThrottlingFilter.UnauthenticatedLookupLimiter unauthenticatedLookupLimiter;

    public BearerTokenAuthFilter(WorkspaceTokenRepository tokenRepository,
                                 ObjectMapper objectMapper) {
        this(tokenRepository, null, objectMapper, ThrottlingFilter.UnauthenticatedLookupLimiter.NOOP);
    }

    public BearerTokenAuthFilter(WorkspaceTokenRepository tokenRepository,
                                 WorkspaceRepository workspaceRepository,
                                 ObjectMapper objectMapper) {
        this(tokenRepository, workspaceRepository, objectMapper, ThrottlingFilter.UnauthenticatedLookupLimiter.NOOP);
    }

    public BearerTokenAuthFilter(WorkspaceTokenRepository tokenRepository,
                                 WorkspaceRepository workspaceRepository,
                                 ObjectMapper objectMapper,
                                 ThrottlingFilter.UnauthenticatedLookupLimiter unauthenticatedLookupLimiter) {
        this.tokenRepository = tokenRepository;
        this.workspaceRepository = workspaceRepository;
        this.objectMapper = objectMapper;
        this.unauthenticatedLookupLimiter = unauthenticatedLookupLimiter != null
                ? unauthenticatedLookupLimiter
                : ThrottlingFilter.UnauthenticatedLookupLimiter.NOOP;
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

        String authHeader = request.getHeader("Authorization");
        if (isAnonymousServiceProviderConfigRequest(request, authHeader, path)) {
            handleAnonymousServiceProviderConfig(request, response, filterChain, workspaceId);
            return;
        }

        String token = extractBearerToken(request, response, authHeader);
        if (token == null) {
            return;
        }

        Workspace tokenWorkspace = authenticateWorkspaceToken(request, response, workspaceId, token);
        if (tokenWorkspace == null) {
            return;
        }

        request.setAttribute("USER_EMAIL", tokenWorkspace.getCreatedByUsername());
        request.setAttribute("WORKSPACE_ID", workspaceId.toString());
        request.setAttribute(AUTHENTICATED_WORKSPACE_ID, workspaceId);
        request.setAttribute(ScimRequestMetricAttributes.AUTHENTICATION, ScimRequestMetricAttributes.AUTH_OK);

        filterChain.doFilter(request, response);
    }

    private static boolean isAnonymousServiceProviderConfigRequest(HttpServletRequest request,
                                                                   String authHeader,
                                                                   String path) {
        return authHeader == null
                && "GET".equalsIgnoreCase(request.getMethod())
                && isServiceProviderConfigEndpoint(path);
    }

    private void handleAnonymousServiceProviderConfig(HttpServletRequest request,
                                                      HttpServletResponse response,
                                                      FilterChain filterChain,
                                                      UUID workspaceId) throws ServletException, IOException {
        ThrottlingFilter.AcquireResult permit = unauthenticatedLookupLimiter.tryAcquireLookupPermit();
        if (!permit.allowed()) {
            writeThrottledError(request, response, permit.retryAfterSeconds());
            return;
        }
        if (workspaceRepository != null && !workspaceRepository.existsById(workspaceId)) {
            request.setAttribute(ScimRequestMetricAttributes.AUTHENTICATION, ScimRequestMetricAttributes.AUTH_FAILED);
            ScimFilterErrorWriter.writeScimError(response, objectMapper, 404, null, "Workspace not found");
            return;
        }
        request.setAttribute("WORKSPACE_ID", workspaceId.toString());
        request.setAttribute(ScimRequestMetricAttributes.AUTHENTICATION, ScimRequestMetricAttributes.AUTH_OK);
        filterChain.doFilter(request, response);
    }

    private String extractBearerToken(HttpServletRequest request,
                                      HttpServletResponse response,
                                      String authHeader) throws IOException {
        if (authHeader == null || !authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            writeUnauthorizedError(request, response, "Missing or invalid Authorization header");
            return null;
        }
        String token = authHeader.substring(7).trim();
        if (token.isEmpty()) {
            writeUnauthorizedError(request, response, "Empty bearer token");
            return null;
        }
        if (token.length() > MAX_BEARER_TOKEN_LENGTH) {
            writeUnauthorizedError(request, response, INVALID_OR_REVOKED_TOKEN_DETAIL);
            return null;
        }
        return token;
    }

    private Workspace authenticateWorkspaceToken(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 UUID workspaceId,
                                                 String token) throws IOException {
        // Validate token (hashed-at-rest only). JOIN FETCH loads workspace in one query.
        String tokenHash = TokenSecurityUtil.sha256Hex(token);
        String tokenCacheKey = workspaceId + ":" + tokenHash;
        boolean knownActive = unauthenticatedLookupLimiter.isKnownActiveToken(tokenCacheKey);
        if (!knownActive) {
            ThrottlingFilter.AcquireResult permit = unauthenticatedLookupLimiter.tryAcquireLookupPermit();
            if (!permit.allowed()) {
                writeThrottledError(request, response, permit.retryAfterSeconds());
                return null;
            }
        }

        Workspace verifiedWorkspace = verifyWorkspaceTokenInDatabase(request, response, workspaceId, tokenHash);
        if (verifiedWorkspace == null) {
            if (knownActive) {
                unauthenticatedLookupLimiter.evictToken(tokenCacheKey);
            }
            return null;
        }

        unauthenticatedLookupLimiter.onValidTokenLookup(tokenCacheKey, !knownActive);
        return verifiedWorkspace;
    }

    private Workspace verifyWorkspaceTokenInDatabase(HttpServletRequest request,
                                                     HttpServletResponse response,
                                                     UUID workspaceId,
                                                     String tokenHash) throws IOException {
        Optional<WorkspaceToken> tokenOpt = tokenRepository.findByTokenHashAndNotRevoked(tokenHash);
        if (tokenOpt.isEmpty()) {
            writeUnauthorizedError(request, response, INVALID_OR_REVOKED_TOKEN_DETAIL);
            return null;
        }

        WorkspaceToken wsToken = tokenOpt.get();
        Workspace tokenWorkspace = wsToken.getWorkspace();
        if (!tokenWorkspace.getId().equals(workspaceId)) {
            writeUnauthorizedError(request, response, "Token does not belong to this workspace");
            return null;
        }

        if (wsToken.getExpiresAt() != null && wsToken.getExpiresAt().isBefore(Instant.now())) {
            writeUnauthorizedError(request, response, "Token has expired");
            return null;
        }

        return tokenWorkspace;
    }

    private void writeThrottledError(HttpServletRequest request,
                                     HttpServletResponse response,
                                     long retryAfterSeconds) throws IOException {
        request.setAttribute(ScimRequestMetricAttributes.THROTTLED, ScimRequestMetricAttributes.THROTTLED_YES);
        ScimFilterErrorWriter.writeScimError(
                response,
                objectMapper,
                HttpStatus.TOO_MANY_REQUESTS.value(),
                null,
                ThrottlingFilter.CAPACITY_ERROR_DETAIL,
                "Retry-After",
                Long.toString(Math.max(1L, retryAfterSeconds)));
    }

    private void writeUnauthorizedError(HttpServletRequest request,
                                        HttpServletResponse response,
                                        String detail) throws IOException {
        request.setAttribute(ScimRequestMetricAttributes.AUTHENTICATION, ScimRequestMetricAttributes.AUTH_FAILED);
        ScimFilterErrorWriter.writeScimError(response, objectMapper, HttpStatus.UNAUTHORIZED.value(), null, detail);
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
