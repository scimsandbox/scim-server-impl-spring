package de.palsoftware.scim.server.impl.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.filter.ThrottlingFilter;
import de.palsoftware.scim.server.impl.metrics.ScimRequestMetricAttributes;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.model.WorkspaceToken;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceTokenRepository;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class BearerTokenAuthFilterTest {

    private WorkspaceTokenRepository tokenRepository;
    private BearerTokenAuthFilter filter;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        tokenRepository = Mockito.mock(WorkspaceTokenRepository.class);
        filter = new BearerTokenAuthFilter(tokenRepository, new ObjectMapper());
        filterChain = Mockito.mock(FilterChain.class);
    }

    @Test
    void missingAuthorizationHeader_Returns401WithWwwAuthenticate() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/" + UUID.randomUUID() + "/scim/v2/Users");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        assertEquals("Bearer", response.getHeader("WWW-Authenticate"));
        assertEquals(ScimRequestMetricAttributes.AUTH_FAILED,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));

        // Non-null non-Bearer headers ("Basic ..." and bare "Bearer" without trailing space) also return 401
        // with 0 DB or lookup-limiter interactions
        AtomicInteger permitsRequested = new AtomicInteger();
        BearerTokenAuthFilter guardedFilter = new BearerTokenAuthFilter(
                tokenRepository,
                null,
                new ObjectMapper(),
                new ThrottlingFilter.UnauthenticatedLookupLimiter() {
                    @Override
                    public boolean isKnownActiveToken(String tokenCacheKey) {
                        return false;
                    }

                    @Override
                    public ThrottlingFilter.AcquireResult tryAcquireLookupPermit() {
                        permitsRequested.incrementAndGet();
                        return ThrottlingFilter.AcquireResult.ALLOWED;
                    }

                    @Override
                    public void onValidTokenLookup(String tokenCacheKey, boolean refundLookupPermit) {
                        // Not expected for malformed Authorization scheme
                    }

                    @Override
                    public void evictToken(String tokenCacheKey) {
                        // Not expected for malformed Authorization scheme
                    }
                });

        for (String badAuthHeader : List.of("Basic dXNlcjpwYXNz", "Bearer")) {
            MockHttpServletRequest badSchemeReq = new MockHttpServletRequest(
                    "GET", "/ws/" + UUID.randomUUID() + "/scim/v2/Users");
            badSchemeReq.addHeader("Authorization", badAuthHeader);
            MockHttpServletResponse badSchemeResp = new MockHttpServletResponse();

            guardedFilter.doFilter(badSchemeReq, badSchemeResp, filterChain);

            assertEquals(401, badSchemeResp.getStatus());
            assertEquals("Bearer", badSchemeResp.getHeader("WWW-Authenticate"));
            assertEquals(ScimRequestMetricAttributes.AUTH_FAILED,
                    badSchemeReq.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
            assertTrue(badSchemeResp.getContentAsString().contains("Missing or invalid Authorization header"));
        }
        assertEquals(0, permitsRequested.get());
        verifyNoInteractions(tokenRepository, filterChain);
    }

    @Test
    void invalidBearerToken_Returns401WithWwwAuthenticate() throws Exception {
        when(tokenRepository.findByTokenHashAndNotRevoked(anyString())).thenReturn(Optional.empty());

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/" + UUID.randomUUID() + "/scim/v2/Users");
        request.addHeader("Authorization", "Bearer invalid-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        assertEquals("Bearer", response.getHeader("WWW-Authenticate"));
        assertEquals(ScimRequestMetricAttributes.AUTH_FAILED,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
    }

    @Test
    void emptyBearerToken_Returns401WithWwwAuthenticate() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/" + UUID.randomUUID() + "/scim/v2/Users");
        request.addHeader("Authorization", "Bearer ");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        assertEquals("Bearer", response.getHeader("WWW-Authenticate"));
        assertEquals(ScimRequestMetricAttributes.AUTH_FAILED,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
    }

    @Test
    void invalidWorkspaceId_Returns404_NoWwwAuthenticate() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/not-a-uuid/scim/v2/Users");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(404, response.getStatus());
        assertNull(response.getHeader("WWW-Authenticate"));
        assertEquals(ScimRequestMetricAttributes.AUTH_FAILED,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
    }

    @Test
    void nonScimPath_PassesThrough() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/actuator/health");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(200, response.getStatus());
        Mockito.verify(filterChain).doFilter(request, response);
    }

    @Test
    void response401_ContainsScimErrorSchema() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/" + UUID.randomUUID() + "/scim/v2/Users");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        assertEquals("application/scim+json;charset=UTF-8", response.getContentType());
        assertEquals("UTF-8", response.getCharacterEncoding());
        assertEquals(ScimRequestMetricAttributes.AUTH_FAILED,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
        String body = response.getContentAsString();
        assertTrue(body.contains("urn:ietf:params:scim:api:messages:2.0:Error"));
        assertTrue(body.contains("\"status\":\"401\""));
    }

    @Test
    void expiredToken_Returns401() throws Exception {
        UUID workspaceId = UUID.randomUUID();
        Workspace ws = new Workspace();
        ws.setId(workspaceId);

        WorkspaceToken wsToken = new WorkspaceToken();
        wsToken.setWorkspace(ws);
        wsToken.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));

        when(tokenRepository.findByTokenHashAndNotRevoked(anyString())).thenReturn(Optional.of(wsToken));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/" + workspaceId + "/scim/v2/Users");
        request.addHeader("Authorization", "Bearer some-valid-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        assertEquals(ScimRequestMetricAttributes.AUTH_FAILED,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
        String body = response.getContentAsString();
        assertTrue(body.contains("Token has expired"));
    }

    @Test
    void validNonExpiredToken_PassesThrough() throws Exception {
        UUID workspaceId = UUID.randomUUID();
        Workspace ws = new Workspace();
        ws.setId(workspaceId);

        WorkspaceToken wsToken = new WorkspaceToken();
        wsToken.setWorkspace(ws);
        wsToken.setExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS));

        when(tokenRepository.findByTokenHashAndNotRevoked(anyString())).thenReturn(Optional.of(wsToken));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/" + workspaceId + "/scim/v2/Users");
        request.addHeader("Authorization", "Bearer some-valid-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(200, response.getStatus());
        assertEquals(workspaceId, request.getAttribute(BearerTokenAuthFilter.AUTHENTICATED_WORKSPACE_ID));
        assertEquals(ScimRequestMetricAttributes.AUTH_OK,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
        Mockito.verify(filterChain).doFilter(request, response);
    }

    @Test
    void caseInsensitiveBearerScheme_PassesThrough() throws Exception {
        UUID workspaceId = UUID.randomUUID();
        Workspace ws = new Workspace();
        ws.setId(workspaceId);

        WorkspaceToken wsToken = new WorkspaceToken();
        wsToken.setWorkspace(ws);
        wsToken.setExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS));

        when(tokenRepository.findByTokenHashAndNotRevoked(anyString())).thenReturn(Optional.of(wsToken));

        for (String prefix : new String[]{"bearer ", "BEARER ", "bEaReR "}) {
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setRequestURI("/ws/" + workspaceId + "/scim/v2/Users");
            request.addHeader("Authorization", prefix + "some-valid-token");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, filterChain);

            assertEquals(200, response.getStatus(), "Failed for scheme prefix: " + prefix);
            assertEquals(ScimRequestMetricAttributes.AUTH_OK,
                    request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
        }
    }

    @Test
    void tokenWithNullExpiresAt_PassesThrough() throws Exception {
        UUID workspaceId = UUID.randomUUID();
        Workspace ws = new Workspace();
        ws.setId(workspaceId);

        WorkspaceToken wsToken = new WorkspaceToken();
        wsToken.setWorkspace(ws);
        wsToken.setExpiresAt(null);

        when(tokenRepository.findByTokenHashAndNotRevoked(anyString())).thenReturn(Optional.of(wsToken));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/" + workspaceId + "/scim/v2/Users");
        request.addHeader("Authorization", "Bearer some-valid-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(200, response.getStatus());
        assertEquals(workspaceId, request.getAttribute(BearerTokenAuthFilter.AUTHENTICATED_WORKSPACE_ID));
        assertEquals(ScimRequestMetricAttributes.AUTH_OK,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
        Mockito.verify(filterChain).doFilter(request, response);
    }

    @Test
    void tokenBelongingToDifferentWorkspace_Returns401() throws Exception {
        UUID requestedWorkspaceId = UUID.randomUUID();
        UUID tokenWorkspaceId = UUID.randomUUID();
        Workspace ws = new Workspace();
        ws.setId(tokenWorkspaceId);

        WorkspaceToken wsToken = new WorkspaceToken();
        wsToken.setWorkspace(ws);
        wsToken.setExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS));

        when(tokenRepository.findByTokenHashAndNotRevoked(anyString())).thenReturn(Optional.of(wsToken));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/" + requestedWorkspaceId + "/scim/v2/Users");
        request.addHeader("Authorization", "Bearer some-valid-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        assertEquals(ScimRequestMetricAttributes.AUTH_FAILED,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
        String body = response.getContentAsString();
        assertTrue(body.contains("Token does not belong to this workspace"));
    }

    @Test
    void anonymousGetServiceProviderConfig_PassesThroughWithoutSettingAuthenticatedWorkspaceId() throws Exception {
        UUID workspaceId = UUID.randomUUID();
        MockHttpServletRequest request = new MockHttpServletRequest("GET",
                "/ws/" + workspaceId + "/scim/v2/ServiceProviderConfig");
        request.setAttribute(BearerTokenAuthFilter.AUTHENTICATED_WORKSPACE_ID, workspaceId);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(200, response.getStatus());
        assertEquals(workspaceId.toString(), request.getAttribute("WORKSPACE_ID"));
        assertNull(request.getAttribute(BearerTokenAuthFilter.AUTHENTICATED_WORKSPACE_ID));
        assertEquals(ScimRequestMetricAttributes.AUTH_OK,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
        Mockito.verify(filterChain).doFilter(request, response);
    }

    @Test
    void invalidTokenOnServiceProviderConfig_StillReturns401() throws Exception {
        when(tokenRepository.findByTokenHashAndNotRevoked(anyString())).thenReturn(Optional.empty());

        UUID workspaceId = UUID.randomUUID();
        MockHttpServletRequest request = new MockHttpServletRequest("GET",
                "/ws/" + workspaceId + "/scim/v2/ServiceProviderConfig");
        request.addHeader("Authorization", "Bearer invalid-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        assertEquals("Bearer", response.getHeader("WWW-Authenticate"));
    }

    @Test
    void anonymousGetServiceProviderConfig_NonExistentWorkspace_Returns404() throws Exception {
        WorkspaceRepository workspaceRepository = Mockito.mock(WorkspaceRepository.class);
        UUID unknownWorkspaceId = UUID.randomUUID();
        when(workspaceRepository.existsById(unknownWorkspaceId)).thenReturn(false);

        BearerTokenAuthFilter wsFilter = new BearerTokenAuthFilter(
                tokenRepository, workspaceRepository, new ObjectMapper());
        MockHttpServletRequest request = new MockHttpServletRequest("GET",
                "/ws/" + unknownWorkspaceId + "/scim/v2/ServiceProviderConfig");
        MockHttpServletResponse response = new MockHttpServletResponse();

        wsFilter.doFilter(request, response, filterChain);

        assertEquals(404, response.getStatus());
        assertNull(response.getHeader("WWW-Authenticate"));
        assertNull(request.getAttribute("WORKSPACE_ID"));
        assertEquals(ScimRequestMetricAttributes.AUTH_FAILED,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
        assertTrue(response.getContentAsString().contains("Workspace not found"));
        Mockito.verifyNoInteractions(filterChain);
    }

    @Test
    void anonymousGetServiceProviderConfig_ExistingWorkspace_PassesThrough() throws Exception {
        WorkspaceRepository workspaceRepository = Mockito.mock(WorkspaceRepository.class);
        UUID workspaceId = UUID.randomUUID();
        when(workspaceRepository.existsById(workspaceId)).thenReturn(true);

        BearerTokenAuthFilter wsFilter = new BearerTokenAuthFilter(
                tokenRepository, workspaceRepository, new ObjectMapper());
        MockHttpServletRequest request = new MockHttpServletRequest("GET",
                "/ws/" + workspaceId + "/scim/v2/ServiceProviderConfig");
        MockHttpServletResponse response = new MockHttpServletResponse();

        wsFilter.doFilter(request, response, filterChain);

        assertEquals(200, response.getStatus());
        assertEquals(workspaceId.toString(), request.getAttribute("WORKSPACE_ID"));
        assertEquals(ScimRequestMetricAttributes.AUTH_OK,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
        Mockito.verify(filterChain).doFilter(request, response);
    }

    @Test
    void oversizedBearerToken_Returns401ImmediatelyWithoutHashingDbOrPermitConsumption() throws Exception {
        UUID workspaceId = UUID.randomUUID();
        AtomicInteger permitsRequested = new AtomicInteger();
        ThrottlingFilter.UnauthenticatedLookupLimiter trackingLimiter = new ThrottlingFilter.UnauthenticatedLookupLimiter() {
            @Override
            public boolean isKnownActiveToken(String tokenCacheKey) {
                return false;
            }

            @Override
            public ThrottlingFilter.AcquireResult tryAcquireLookupPermit() {
                permitsRequested.incrementAndGet();
                return ThrottlingFilter.AcquireResult.ALLOWED;
            }

            @Override
            public void onValidTokenLookup(String tokenCacheKey, boolean refundLookupPermit) {
                // Not expected for oversized token
            }

            @Override
            public void evictToken(String tokenCacheKey) {
                // Not expected for oversized token
            }
        };
        BearerTokenAuthFilter guardedFilter = new BearerTokenAuthFilter(
                tokenRepository, null, new ObjectMapper(), trackingLimiter);

        // 1. 513-char and 8192-char tokens are rejected before SHA-256, cache, or DB lookup
        for (int len : List.of(BearerTokenAuthFilter.MAX_BEARER_TOKEN_LENGTH + 1, 8192)) {
            MockHttpServletRequest request = new MockHttpServletRequest(
                    "GET", "/ws/" + workspaceId + "/scim/v2/Users");
            request.addHeader("Authorization", "Bearer " + "x".repeat(len));
            MockHttpServletResponse response = new MockHttpServletResponse();

            guardedFilter.doFilter(request, response, filterChain);

            assertEquals(401, response.getStatus());
            assertEquals("Bearer", response.getHeader("WWW-Authenticate"));
            assertEquals(ScimRequestMetricAttributes.AUTH_FAILED,
                    request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
            assertTrue(response.getContentAsString().contains("Invalid or revoked token"));
        }
        assertEquals(0, permitsRequested.get());
        verifyNoInteractions(tokenRepository, filterChain);

        // 2. Exact 512-char token is allowed through to normal verification
        Workspace ws = new Workspace();
        ws.setId(workspaceId);
        String maxAllowedToken = "v".repeat(BearerTokenAuthFilter.MAX_BEARER_TOKEN_LENGTH);
        WorkspaceToken wsToken = new WorkspaceToken();
        wsToken.setWorkspace(ws);
        wsToken.setTokenHash(TokenSecurityUtil.sha256Hex(maxAllowedToken));
        when(tokenRepository.findByTokenHashAndNotRevoked(wsToken.getTokenHash())).thenReturn(Optional.of(wsToken));

        MockHttpServletRequest exactMaxReq = new MockHttpServletRequest(
                "GET", "/ws/" + workspaceId + "/scim/v2/Users");
        exactMaxReq.addHeader("Authorization", "Bearer " + maxAllowedToken);
        MockHttpServletResponse exactMaxResp = new MockHttpServletResponse();
        guardedFilter.doFilter(exactMaxReq, exactMaxResp, filterChain);

        assertEquals(200, exactMaxResp.getStatus());
        assertEquals(1, permitsRequested.get());
    }

    @Test
    void coldMissValidTokens_RefundLookupPermitAndWarmHashedCacheKeyOnly() throws Exception {
        UUID workspaceId = UUID.randomUUID();
        Workspace ws = new Workspace();
        ws.setId(workspaceId);

        // Pod-wide unauthenticated lookup burst = 1 (0.5 RPS -> Retry-After = 2s)
        ThrottlingFilter.UnauthenticatedLookupLimiter limiter =
                ThrottlingFilter.createUnauthenticatedLookupLimiter(200.0, 200, 0.5, 1, Duration.ZERO);
        BearerTokenAuthFilter guardedFilter = new BearerTokenAuthFilter(
                tokenRepository, null, new ObjectMapper(), limiter);

        // Even with burst = 1, 3 distinct valid tokens all succeed because each cold-miss permit is refunded!
        for (int i = 1; i <= 3; i++) {
            String rawToken = "active-token-" + i;
            String tokenHash = TokenSecurityUtil.sha256Hex(rawToken);
            WorkspaceToken wsToken = new WorkspaceToken();
            wsToken.setWorkspace(ws);
            wsToken.setTokenHash(tokenHash);
            when(tokenRepository.findByTokenHashAndNotRevoked(tokenHash)).thenReturn(Optional.of(wsToken));

            MockHttpServletRequest req = new MockHttpServletRequest("GET", "/ws/" + workspaceId + "/scim/v2/Users");
            req.addHeader("Authorization", "Bearer " + rawToken);
            MockHttpServletResponse resp = new MockHttpServletResponse();
            guardedFilter.doFilter(req, resp, filterChain);

            assertEquals(200, resp.getStatus());
            assertTrue(limiter.isKnownActiveToken(workspaceId + ":" + tokenHash));
            assertFalse(limiter.isKnownActiveToken(rawToken));
            assertFalse(limiter.isKnownActiveToken(UUID.randomUUID() + ":" + tokenHash));
        }

        // Null limiter in 4-arg constructor defaults safely to NOOP
        BearerTokenAuthFilter nullLimiterFilter = new BearerTokenAuthFilter(
                tokenRepository, null, new ObjectMapper(), null);
        MockHttpServletRequest okReq = new MockHttpServletRequest("GET", "/ws/" + workspaceId + "/scim/v2/Users");
        okReq.addHeader("Authorization", "Bearer active-token-1");
        MockHttpServletResponse okResp = new MockHttpServletResponse();
        nullLimiterFilter.doFilter(okReq, okResp, filterChain);
        assertEquals(200, okResp.getStatus());
    }

    @Test
    void expiredOrWrongWorkspaceWarmToken_ImmediatelyReturns401AndEvictsHintCacheEntry() throws Exception {
        UUID workspaceA = UUID.randomUUID();
        UUID workspaceB = UUID.randomUUID();
        Workspace wsA = new Workspace();
        wsA.setId(workspaceA);
        Workspace wsB = new Workspace();
        wsB.setId(workspaceB);

        ThrottlingFilter.UnauthenticatedLookupLimiter limiter =
                ThrottlingFilter.createUnauthenticatedLookupLimiter(200.0, 200, 0.5, 1, Duration.ZERO);
        BearerTokenAuthFilter guardedFilter = new BearerTokenAuthFilter(
                tokenRepository, null, new ObjectMapper(), limiter);

        // 1. Warm valid token on workspaceA (burst=1 permit acquired then refunded -> 1 permit left)
        String rawExpiringToken = "soon-expiring-token";
        String expiringHash = TokenSecurityUtil.sha256Hex(rawExpiringToken);
        WorkspaceToken expiringEntity = new WorkspaceToken();
        expiringEntity.setWorkspace(wsA);
        expiringEntity.setTokenHash(expiringHash);
        expiringEntity.setExpiresAt(Instant.now().plus(1, ChronoUnit.HOURS));
        when(tokenRepository.findByTokenHashAndNotRevoked(expiringHash)).thenReturn(Optional.of(expiringEntity));

        MockHttpServletRequest warmReq = new MockHttpServletRequest("GET", "/ws/" + workspaceA + "/scim/v2/Users");
        warmReq.addHeader("Authorization", "Bearer " + rawExpiringToken);
        MockHttpServletResponse warmResp = new MockHttpServletResponse();
        guardedFilter.doFilter(warmReq, warmResp, filterChain);
        assertEquals(200, warmResp.getStatus());
        assertTrue(limiter.isKnownActiveToken(workspaceA + ":" + expiringHash));

        // Pre-warm a wrong-workspace key as well before draining the 1 lookup permit
        String rawWrongWsToken = "wrong-workspace-token";
        String wrongWsHash = TokenSecurityUtil.sha256Hex(rawWrongWsToken);
        WorkspaceToken wrongWsEntity = new WorkspaceToken();
        wrongWsEntity.setWorkspace(wsB);
        wrongWsEntity.setTokenHash(wrongWsHash);
        when(tokenRepository.findByTokenHashAndNotRevoked(wrongWsHash)).thenReturn(Optional.of(wrongWsEntity));
        limiter.onValidTokenLookup(workspaceA + ":" + wrongWsHash, false);
        assertTrue(limiter.isKnownActiveToken(workspaceA + ":" + wrongWsHash));

        // Drain the single lookup permit via 1 invalid-token request (401)
        when(tokenRepository.findByTokenHashAndNotRevoked(TokenSecurityUtil.sha256Hex("bad-drain")))
                .thenReturn(Optional.empty());
        MockHttpServletRequest drainReq = new MockHttpServletRequest("GET", "/ws/" + workspaceA + "/scim/v2/Users");
        drainReq.addHeader("Authorization", "Bearer bad-drain");
        MockHttpServletResponse drainResp = new MockHttpServletResponse();
        guardedFilter.doFilter(drainReq, drainResp, filterChain);
        assertEquals(401, drainResp.getStatus());

        // 2. Expire the warm token in DB -> very next request returns 401 AND evicts cache key;
        //    following request hits exhausted lookup bucket (429, Retry-After: 2) with 0 DB queries!
        expiringEntity.setExpiresAt(Instant.now().minus(5, ChronoUnit.SECONDS));
        MockHttpServletRequest expiredReq = new MockHttpServletRequest("GET", "/ws/" + workspaceA + "/scim/v2/Users");
        expiredReq.addHeader("Authorization", "Bearer " + rawExpiringToken);
        MockHttpServletResponse expiredResp = new MockHttpServletResponse();
        guardedFilter.doFilter(expiredReq, expiredResp, filterChain);
        assertEquals(401, expiredResp.getStatus());
        assertTrue(expiredResp.getContentAsString().contains("Token has expired"));
        assertFalse(limiter.isKnownActiveToken(workspaceA + ":" + expiringHash));

        Mockito.clearInvocations(tokenRepository);
        MockHttpServletRequest postEvictExpiredReq = new MockHttpServletRequest(
                "GET", "/ws/" + workspaceA + "/scim/v2/Users");
        postEvictExpiredReq.addHeader("Authorization", "Bearer " + rawExpiringToken);
        MockHttpServletResponse postEvictExpiredResp = new MockHttpServletResponse();
        guardedFilter.doFilter(postEvictExpiredReq, postEvictExpiredResp, filterChain);
        assertEquals(429, postEvictExpiredResp.getStatus());
        assertEquals("2", postEvictExpiredResp.getHeader("Retry-After"));
        verifyNoInteractions(tokenRepository);

        // 3. Warm wrong-workspace entry -> returns 401 AND evicts cache key; next request gets 429 with 0 DB queries!
        MockHttpServletRequest wrongWsReq = new MockHttpServletRequest("GET", "/ws/" + workspaceA + "/scim/v2/Users");
        wrongWsReq.addHeader("Authorization", "Bearer " + rawWrongWsToken);
        MockHttpServletResponse wrongWsResp = new MockHttpServletResponse();
        guardedFilter.doFilter(wrongWsReq, wrongWsResp, filterChain);
        assertEquals(401, wrongWsResp.getStatus());
        assertTrue(wrongWsResp.getContentAsString().contains("Token does not belong to this workspace"));
        assertFalse(limiter.isKnownActiveToken(workspaceA + ":" + wrongWsHash));

        Mockito.clearInvocations(tokenRepository);
        MockHttpServletRequest postEvictWrongWsReq = new MockHttpServletRequest(
                "GET", "/ws/" + workspaceA + "/scim/v2/Users");
        postEvictWrongWsReq.addHeader("Authorization", "Bearer " + rawWrongWsToken);
        MockHttpServletResponse postEvictWrongWsResp = new MockHttpServletResponse();
        guardedFilter.doFilter(postEvictWrongWsReq, postEvictWrongWsResp, filterChain);
        assertEquals(429, postEvictWrongWsResp.getStatus());
        verifyNoInteractions(tokenRepository);
    }

    @Test
    void anonymousServiceProviderConfig_ThrottlesWhenLookupBucketExhaustedBeforeExistsById() throws Exception {
        WorkspaceRepository workspaceRepository = Mockito.mock(WorkspaceRepository.class);
        UUID workspaceId = UUID.randomUUID();
        when(workspaceRepository.existsById(workspaceId)).thenReturn(true);

        // Burst = 2 (0.5 RPS -> Retry-After = 2s): covers standard + compat /ms/ServiceProviderConfig/
        ThrottlingFilter.UnauthenticatedLookupLimiter limiter =
                ThrottlingFilter.createUnauthenticatedLookupLimiter(200.0, 200, 0.5, 2, Duration.ZERO);
        BearerTokenAuthFilter wsFilter = new BearerTokenAuthFilter(
                tokenRepository, workspaceRepository, new ObjectMapper(), limiter);

        for (String uri : List.of(
                "/ws/" + workspaceId + "/scim/v2/ServiceProviderConfig",
                "/ws/" + workspaceId + "/scim/v2/ms/ServiceProviderConfig/")) {
            MockHttpServletRequest okReq = new MockHttpServletRequest("GET", uri);
            MockHttpServletResponse okResp = new MockHttpServletResponse();
            wsFilter.doFilter(okReq, okResp, filterChain);
            assertEquals(200, okResp.getStatus());
        }

        // 3rd anonymous GET /ServiceProviderConfig is rejected BEFORE workspaceRepository.existsById!
        Mockito.clearInvocations(workspaceRepository);
        MockHttpServletRequest throttledReq = new MockHttpServletRequest(
                "GET", "/ws/" + workspaceId + "/scim/v2/ms/ServiceProviderConfig");
        MockHttpServletResponse throttledResp = new MockHttpServletResponse();
        wsFilter.doFilter(throttledReq, throttledResp, filterChain);

        assertEquals(429, throttledResp.getStatus());
        assertEquals("2", throttledResp.getHeader("Retry-After"));
        assertEquals(ScimRequestMetricAttributes.THROTTLED_YES,
                throttledReq.getAttribute(ScimRequestMetricAttributes.THROTTLED));
        assertNull(throttledReq.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
        assertTrue(throttledResp.getContentAsString().contains(ThrottlingFilter.CAPACITY_ERROR_DETAIL));
        verifyNoInteractions(workspaceRepository);

        // Non-GET or unknown 7-segment non-compat ServiceProviderConfig without Authorization returns 401
        MockHttpServletRequest postSpc = new MockHttpServletRequest(
                "POST", "/ws/" + workspaceId + "/scim/v2/ServiceProviderConfig");
        MockHttpServletResponse postSpcResp = new MockHttpServletResponse();
        wsFilter.doFilter(postSpc, postSpcResp, filterChain);
        assertEquals(401, postSpcResp.getStatus());

        MockHttpServletRequest unknownCompatSpc = new MockHttpServletRequest(
                "GET", "/ws/" + workspaceId + "/scim/v2/unknown-vendor/ServiceProviderConfig");
        MockHttpServletResponse unknownCompatResp = new MockHttpServletResponse();
        wsFilter.doFilter(unknownCompatSpc, unknownCompatResp, filterChain);
        assertEquals(401, unknownCompatResp.getStatus());
    }
}
