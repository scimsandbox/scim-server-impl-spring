package de.palsoftware.scim.server.impl.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.metrics.ScimOperationMetricsFilter;
import de.palsoftware.scim.server.impl.metrics.ScimRequestMetricAttributes;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.model.WorkspaceToken;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceTokenRepository;
import de.palsoftware.scim.server.impl.security.BearerTokenAuthFilter;
import de.palsoftware.scim.server.impl.security.TokenSecurityUtil;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class ThrottlingFilterTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        filterChain = Mockito.mock(FilterChain.class);
    }

    @Test
    void availablePermit_PassesThroughByClientIpAndNormalizesWaitTimeoutBounds() throws Exception {
        AtomicReference<String> observedKey = new AtomicReference<>();
        AtomicReference<Duration> observedTimeout = new AtomicReference<>();
        ThrottlingFilter filter = new ThrottlingFilter((key, timeout) -> {
            observedKey.set(key);
            observedTimeout.set(timeout);
            return ThrottlingFilter.AcquireResult.ALLOWED;
        }, null, objectMapper);

        UUID wsId = UUID.randomUUID();
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/ws/" + wsId + "/scim/v2/Users");
        request.setRemoteAddr("198.51.100.77");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals("ip:198.51.100.77", observedKey.get());
        assertEquals("ip:198.51.100.77", request.getAttribute(ThrottlingFilter.RESOLVED_CLIENT_IP_KEY_ATTRIBUTE));
        assertEquals(Duration.ZERO, observedTimeout.get());
        assertEquals(ScimRequestMetricAttributes.THROTTLED_NO,
                request.getAttribute(ScimRequestMetricAttributes.THROTTLED));
        verify(filterChain).doFilter(request, response);

        assertThat(ThrottlingFilter.resolveWaitTimeout(null)).isEqualTo(Duration.ZERO);
        assertThat(ThrottlingFilter.resolveWaitTimeout(Duration.ofMillis(-100))).isEqualTo(Duration.ZERO);
        assertThat(ThrottlingFilter.resolveWaitTimeout(Duration.ZERO)).isEqualTo(Duration.ZERO);
        assertThat(ThrottlingFilter.resolveWaitTimeout(Duration.ofMillis(250))).isEqualTo(Duration.ofMillis(250));
        assertThat(ThrottlingFilter.resolveWaitTimeout(Duration.ofSeconds(30)))
                .isEqualTo(ThrottlingFilter.MAX_WAIT_TIMEOUT);
    }

    @Test
    void dynamicRetryAfter_ComputesCeilingSecondsForSubOneRpsAndOneSecondForOneOrHigherRps() throws Exception {
        AtomicLong fakeNanos = new AtomicLong(0L);

        // 1. 0.2 RPS (1 token every 5s), burst 1 -> after 1st request, Retry-After = ceil(1.0 / 0.2) = 5s;
        //    after 2s (0.4 tokens refilled, deficit 0.6), Retry-After = ceil(0.6 / 0.2) = 3s
        ThrottlingFilter slowFilter = new ThrottlingFilter(
                ThrottlingFilter.createPreAuthLimiter(0.2, 1, 0.2, 1, fakeNanos::get),
                Duration.ZERO,
                objectMapper);
        String path = "/ws/" + UUID.randomUUID() + "/scim/v2/Users";

        MockHttpServletRequest req1 = new MockHttpServletRequest("GET", path);
        req1.setRemoteAddr("198.51.100.1");
        MockHttpServletResponse resp1 = new MockHttpServletResponse();
        slowFilter.doFilter(req1, resp1, filterChain);
        assertThat(resp1.getStatus()).isEqualTo(200);

        MockHttpServletRequest req2 = new MockHttpServletRequest("GET", path);
        req2.setRemoteAddr("198.51.100.1");
        MockHttpServletResponse resp2 = new MockHttpServletResponse();
        slowFilter.doFilter(req2, resp2, filterChain);
        assertThat(resp2.getStatus()).isEqualTo(429);
        assertThat(resp2.getHeader("Retry-After")).isEqualTo("5");
        assertEquals("application/scim+json;charset=UTF-8", resp2.getContentType());
        assertEquals(ScimRequestMetricAttributes.THROTTLED_YES,
                req2.getAttribute(ScimRequestMetricAttributes.THROTTLED));
        assertTrue(resp2.getContentAsString().contains("\"status\":\"429\""));
        assertTrue(resp2.getContentAsString().contains("Too many requests. Try again later."));

        fakeNanos.addAndGet(Duration.ofSeconds(2).toNanos());
        MockHttpServletRequest req3 = new MockHttpServletRequest("GET", path);
        req3.setRemoteAddr("198.51.100.1");
        MockHttpServletResponse resp3 = new MockHttpServletResponse();
        slowFilter.doFilter(req3, resp3, filterChain);
        assertThat(resp3.getStatus()).isEqualTo(429);
        assertThat(resp3.getHeader("Retry-After")).isEqualTo("3");

        // 2. >= 1.0 RPS (e.g. 10 RPS) -> Retry-After = 1
        ThrottlingFilter fastFilter = new ThrottlingFilter(
                ThrottlingFilter.createPreAuthLimiter(10.0, 1, 10.0, 1, fakeNanos::get),
                Duration.ZERO,
                objectMapper);
        MockHttpServletRequest fReq1 = new MockHttpServletRequest("GET", path);
        fReq1.setRemoteAddr("198.51.100.2");
        fastFilter.doFilter(fReq1, new MockHttpServletResponse(), filterChain);

        MockHttpServletRequest fReq2 = new MockHttpServletRequest("GET", path);
        fReq2.setRemoteAddr("198.51.100.2");
        MockHttpServletResponse fResp2 = new MockHttpServletResponse();
        fastFilter.doFilter(fReq2, fResp2, filterChain);
        assertThat(fResp2.getStatus()).isEqualTo(429);
        assertThat(fResp2.getHeader("Retry-After")).isEqualTo("1");
    }

    @Test
    void actuatorEndpoints_SkipThrottlingAndWorkspaceRateLimitWithoutConsumingPermits() throws Exception {
        AtomicInteger permitsAcquired = new AtomicInteger();
        ThrottlingFilter.KeyedPermitLimiter countingLimiter = (_, _) -> {
            permitsAcquired.incrementAndGet();
            return ThrottlingFilter.AcquireResult.rejected(1);
        };
        ThrottlingFilter throttlingFilter = new ThrottlingFilter(countingLimiter, Duration.ZERO, objectMapper);
        WorkspaceRateLimitFilter wsFilter = new WorkspaceRateLimitFilter(countingLimiter, Duration.ZERO, objectMapper);

        for (String actuatorPath : List.of("/actuator", "/actuator/health", "/actuator/health/liveness", "/actuator/prometheus")) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", actuatorPath);
            request.setAttribute(BearerTokenAuthFilter.AUTHENTICATED_WORKSPACE_ID, UUID.randomUUID());
            MockHttpServletResponse response = new MockHttpServletResponse();
            throttlingFilter.doFilter(request, response, (r2, s2) -> wsFilter.doFilter(r2, s2, filterChain));
            assertEquals(200, response.getStatus());
        }

        assertEquals(0, permitsAcquired.get());
        verify(filterChain, times(4)).doFilter(Mockito.any(), Mockito.any());
    }

    @Test
    void threeTierDefense_OutsiderInvalidTokenFloodAndRandomUuidFloodNeverLockOutValidWorkspaceCaller() throws Exception {
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        ScimOperationMetricsFilter metricsFilter = new ScimOperationMetricsFilter(meterRegistry);
        AtomicLong fakeNanos = new AtomicLong(0L);

        // Post-auth Global: 100 RPS burst ONLY 3; Pre-auth Per-IP: 10 RPS burst 2;
        // Unauthenticated lookup limiter: 0.5 RPS (Retry-After = 2s), burst 10; Post-auth Per-Workspace: 10 RPS burst 3
        ThrottlingFilter preAuthFilter = new ThrottlingFilter(
                ThrottlingFilter.createPreAuthLimiter(100.0, 3, 10.0, 2, fakeNanos::get),
                Duration.ZERO,
                objectMapper);
        ThrottlingFilter.UnauthenticatedLookupLimiter unauthLookupLimiter =
                ThrottlingFilter.createUnauthenticatedLookupLimiter(
                        new ThrottlingFilter.SubRateLimit(0.5, 10),
                        new ThrottlingFilter.SubRateLimit(0.5, 2),
                        Duration.ZERO,
                        fakeNanos::get);
        WorkspaceRateLimitFilter postAuthWsFilter = new WorkspaceRateLimitFilter(
                ThrottlingFilter.createPostAuthLimiter(100.0, 3, 10.0, 3, fakeNanos::get),
                Duration.ZERO,
                objectMapper);

        UUID workspaceA = UUID.randomUUID();
        Workspace wsA = new Workspace();
        wsA.setId(workspaceA);
        wsA.setCreatedByUsername("tenant-a");

        String rawValidTokenA = "valid-token-workspace-a";
        String validHashA = TokenSecurityUtil.sha256Hex(rawValidTokenA);
        WorkspaceToken tokenEntityA = new WorkspaceToken();
        tokenEntityA.setWorkspace(wsA);
        tokenEntityA.setTokenHash(validHashA);
        tokenEntityA.setExpiresAt(Instant.now().plus(1, ChronoUnit.DAYS));

        AtomicBoolean tokenRevoked = new AtomicBoolean(false);
        WorkspaceTokenRepository tokenRepository = Mockito.mock(WorkspaceTokenRepository.class);
        when(tokenRepository.findByTokenHashAndNotRevoked(anyString())).thenAnswer(inv -> {
            String hash = inv.getArgument(0);
            return (!tokenRevoked.get() && validHashA.equals(hash)) ? Optional.of(tokenEntityA) : Optional.empty();
        });
        WorkspaceRepository workspaceRepository = Mockito.mock(WorkspaceRepository.class);
        when(workspaceRepository.existsById(workspaceA)).thenReturn(true);

        BearerTokenAuthFilter bearerFilter = new BearerTokenAuthFilter(
                tokenRepository, workspaceRepository, objectMapper, unauthLookupLimiter);

        FilterChain fullChain = (req, res) -> preAuthFilter.doFilter(
                req, res, (r2, s2) -> bearerFilter.doFilter(
                        r2, s2, (r3, s3) -> postAuthWsFilter.doFilter(r3, s3, filterChain)));

        // 0. Warm active Workspace A BEFORE the attack:
        //    Cold-miss lookup permit is refunded (net 0 lookup permits used, 10/10 remain!),
        //    then advance clock 1s so Workspace A's post-auth 3-token burst is back to full 3/3.
        MockHttpServletRequest warmReq = new MockHttpServletRequest("GET", "/ws/" + workspaceA + "/scim/v2/Users");
        warmReq.setRemoteAddr("198.51.100.9");
        warmReq.addHeader("Authorization", "Bearer " + rawValidTokenA);
        MockHttpServletResponse warmResp = new MockHttpServletResponse();
        metricsFilter.doFilter(warmReq, warmResp, fullChain);
        assertThat(warmResp.getStatus()).isEqualTo(200);
        assertThat(unauthLookupLimiter.isKnownActiveToken(workspaceA + ":" + validHashA)).isTrue();
        fakeNanos.addAndGet(Duration.ofSeconds(1).toNanos());

        // 1. Attacker IP 203.0.113.66 floods Workspace A with invalid tokens:
        //    First 2 hit 401 (consuming 2/10 unauth lookup permits -> 8 remain);
        //    next 5 hit 429 in pre-auth ThrottlingFilter with 0 DB queries!
        for (int i = 0; i < 2; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest("GET", "/ws/" + workspaceA + "/scim/v2/Users");
            req.setRemoteAddr("203.0.113.66");
            req.addHeader("Authorization", "Bearer bad-" + i);
            MockHttpServletResponse resp = new MockHttpServletResponse();
            metricsFilter.doFilter(req, resp, fullChain);
            assertThat(resp.getStatus()).isEqualTo(401);
        }
        Mockito.clearInvocations(tokenRepository);

        for (int i = 0; i < 5; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest("GET", "/ws/" + workspaceA + "/scim/v2/Users");
            req.setRemoteAddr("203.0.113.66");
            req.addHeader("Authorization", "Bearer bad-flood-" + i);
            MockHttpServletResponse resp = new MockHttpServletResponse();
            metricsFilter.doFilter(req, resp, fullChain);
            assertThat(resp.getStatus()).isEqualTo(429);
        }
        verifyNoInteractions(tokenRepository);

        // 2. Same attacker IP 203.0.113.66 rotates random workspace UUIDs -> STILL 429 with 0 DB queries!
        for (int i = 0; i < 4; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest(
                    "GET", "/ws/" + UUID.randomUUID() + "/scim/v2/Users");
            req.setRemoteAddr("203.0.113.66");
            req.addHeader("Authorization", "Bearer random-ws-flood-" + i);
            MockHttpServletResponse resp = new MockHttpServletResponse();
            metricsFilter.doFilter(req, resp, fullChain);
            assertThat(resp.getStatus()).isEqualTo(429);
        }
        verifyNoInteractions(tokenRepository);

        // 3. Distributed unauthenticated botnet flood across 50 distinct IPs & IPv6 /48 prefixes
        //    plus 10 anonymous ServiceProviderConfig discovery requests:
        //    Capped at the remaining 8 of 10 pod-wide unauthenticated lookup permits, after which
        //    all remaining botnet + anonymous requests get 429 (Retry-After: 2, throttled=yes,
        //    authentication=unknown) with 0 DB queries!
        for (int idx = 1; idx <= 3; idx++) {
            MockHttpServletRequest v4Unauth = new MockHttpServletRequest("GET", "/ws/" + workspaceA + "/scim/v2/Users");
            v4Unauth.setRemoteAddr("203.0.114." + idx);
            v4Unauth.addHeader("Authorization", "Bearer botnet-v4-" + idx);
            MockHttpServletResponse v4Resp = new MockHttpServletResponse();
            metricsFilter.doFilter(v4Unauth, v4Resp, fullChain);
            assertThat(v4Resp.getStatus()).isEqualTo(401);

            MockHttpServletRequest v6Unauth = new MockHttpServletRequest("GET", "/ws/" + workspaceA + "/scim/v2/Users");
            v6Unauth.setRemoteAddr("2001:db8:bad:" + Integer.toHexString(idx) + "::1");
            v6Unauth.addHeader("Authorization", "Bearer botnet-v6-" + idx);
            MockHttpServletResponse v6Resp = new MockHttpServletResponse();
            metricsFilter.doFilter(v6Unauth, v6Resp, fullChain);
            assertThat(v6Resp.getStatus()).isEqualTo(401);
        }
        for (int idx = 1; idx <= 2; idx++) {
            MockHttpServletRequest anonOk = new MockHttpServletRequest(
                    "GET", "/ws/" + workspaceA + "/scim/v2/ServiceProviderConfig");
            anonOk.setRemoteAddr("198.18.0." + idx);
            MockHttpServletResponse anonResp = new MockHttpServletResponse();
            metricsFilter.doFilter(anonOk, anonResp, fullChain);
            assertThat(anonResp.getStatus()).isEqualTo(200);
        }

        // All 10/10 pod-wide unauthenticated lookup permits are now exhausted:
        // Remaining 44 botnet invalid-token requests + 8 anonymous discovery requests get 429 with 0 DB queries!
        Mockito.clearInvocations(tokenRepository);
        Mockito.clearInvocations(workspaceRepository);
        double throttledYesBefore = meterRegistry.counter("scim.operation.throttled", "state", "yes").count();
        double authUnknownBefore = meterRegistry.counter("scim.operation.authentication", "state", "unknown").count();
        double authFailedBefore = meterRegistry.counter("scim.operation.authentication", "state", "failed").count();

        for (int idx = 4; idx <= 25; idx++) {
            MockHttpServletRequest v4Bot = new MockHttpServletRequest("GET", "/ws/" + workspaceA + "/scim/v2/Users");
            v4Bot.setRemoteAddr("203.0.114." + idx);
            v4Bot.addHeader("Authorization", "Bearer botnet-v4-" + idx);
            MockHttpServletResponse v4Resp = new MockHttpServletResponse();
            metricsFilter.doFilter(v4Bot, v4Resp, fullChain);
            assertThat(v4Resp.getStatus()).isEqualTo(429);
            assertThat(v4Resp.getHeader("Retry-After")).isEqualTo("2");

            MockHttpServletRequest v6Bot = new MockHttpServletRequest("GET", "/ws/" + workspaceA + "/scim/v2/Users");
            v6Bot.setRemoteAddr("2001:db8:bad:" + Integer.toHexString(idx) + "::1");
            v6Bot.addHeader("Authorization", "Bearer botnet-v6-" + idx);
            MockHttpServletResponse v6Resp = new MockHttpServletResponse();
            metricsFilter.doFilter(v6Bot, v6Resp, fullChain);
            assertThat(v6Resp.getStatus()).isEqualTo(429);
            assertThat(v6Resp.getHeader("Retry-After")).isEqualTo("2");
        }
        for (int idx = 3; idx <= 10; idx++) {
            MockHttpServletRequest anonFlood = new MockHttpServletRequest(
                    "GET", "/ws/" + workspaceA + "/scim/v2/ServiceProviderConfig");
            anonFlood.setRemoteAddr("198.18.0." + idx);
            MockHttpServletResponse anonResp = new MockHttpServletResponse();
            metricsFilter.doFilter(anonFlood, anonResp, fullChain);
            assertThat(anonResp.getStatus()).isEqualTo(429);
            assertThat(anonResp.getHeader("Retry-After")).isEqualTo("2");
        }

        verifyNoInteractions(tokenRepository, workspaceRepository);
        assertThat(meterRegistry.counter("scim.operation.throttled", "state", "yes").count() - throttledYesBefore)
                .isEqualTo(52.0);
        assertThat(meterRegistry.counter("scim.operation.authentication", "state", "unknown").count() - authUnknownBefore)
                .isEqualTo(52.0);
        assertThat(meterRegistry.counter("scim.operation.authentication", "state", "failed").count() - authFailedBefore)
                .isZero();

        // 4. Legitimate Workspace A client (warm in verifiedTokenHashes) bypasses the exhausted
        //    UnauthenticatedLookupLimiter, still verifies against tokenRepository on every request,
        //    and STILL has ALL 3 post-auth global + workspace permits!
        for (String legitIp : List.of("198.51.100.10", "198.51.100.10", "198.51.100.11")) {
            MockHttpServletRequest legitReq = new MockHttpServletRequest("GET", "/ws/" + workspaceA + "/scim/v2/Users");
            legitReq.setRemoteAddr(legitIp);
            legitReq.addHeader("Authorization", "Bearer " + rawValidTokenA);
            MockHttpServletResponse legitResp = new MockHttpServletResponse();
            metricsFilter.doFilter(legitReq, legitResp, fullChain);
            assertThat(legitResp.getStatus()).isEqualTo(200);
        }
        verify(tokenRepository, times(3)).findByTokenHashAndNotRevoked(validHashA);

        // 5. 4th authenticated request on Workspace A (even from fresh IP 198.51.100.11) hits post-auth cap (429)!
        MockHttpServletRequest overWsCap = new MockHttpServletRequest("GET", "/ws/" + workspaceA + "/scim/v2/Users");
        overWsCap.setRemoteAddr("198.51.100.11");
        overWsCap.addHeader("Authorization", "Bearer " + rawValidTokenA);
        MockHttpServletResponse overWsResp = new MockHttpServletResponse();
        metricsFilter.doFilter(overWsCap, overWsResp, fullChain);
        assertThat(overWsResp.getStatus()).isEqualTo(429);

        // 6. Instantaneous revocation (0 ms stale window) + immediate cache eviction:
        //    Advance 100ms (refills 1.0 post-auth token at 10 RPS, while unauthLookupLimiter at 0.5 RPS
        //    only refills 0.05 tokens and remains exhausted!).
        fakeNanos.addAndGet(Duration.ofMillis(100).toNanos());
        tokenRevoked.set(true);

        MockHttpServletRequest firstAfterRevoke = new MockHttpServletRequest(
                "GET", "/ws/" + workspaceA + "/scim/v2/Users");
        firstAfterRevoke.setRemoteAddr("198.51.100.12");
        firstAfterRevoke.addHeader("Authorization", "Bearer " + rawValidTokenA);
        MockHttpServletResponse firstRevokeResp = new MockHttpServletResponse();
        metricsFilter.doFilter(firstAfterRevoke, firstRevokeResp, fullChain);
        assertThat(firstRevokeResp.getStatus()).isEqualTo(401);
        assertThat(unauthLookupLimiter.isKnownActiveToken(workspaceA + ":" + validHashA)).isFalse();

        // Subsequent request with the now-evicted revoked token hits exhausted unauthLookupLimiter -> 429 with 0 DB queries!
        Mockito.clearInvocations(tokenRepository);
        MockHttpServletRequest secondAfterRevoke = new MockHttpServletRequest(
                "GET", "/ws/" + workspaceA + "/scim/v2/Users");
        secondAfterRevoke.setRemoteAddr("198.51.100.12");
        secondAfterRevoke.addHeader("Authorization", "Bearer " + rawValidTokenA);
        MockHttpServletResponse secondRevokeResp = new MockHttpServletResponse();
        metricsFilter.doFilter(secondAfterRevoke, secondRevokeResp, fullChain);
        assertThat(secondRevokeResp.getStatus()).isEqualTo(429);
        assertThat(secondRevokeResp.getHeader("Retry-After")).isEqualTo("2");
        verifyNoInteractions(tokenRepository);
    }

    @Test
    void postAuthGlobalCap_CapsAggregateAuthenticatedWorkspacesAndRefundsWorkspaceBucketOnGlobalRejection() throws Exception {
        AtomicLong fakeNanos = new AtomicLong(0L);
        // Post-auth Global: 0.25 RPS (Retry-After = 4s), burst = 2; Per-Workspace: 10 RPS, burst = 2
        WorkspaceRateLimitFilter postAuthFilter = new WorkspaceRateLimitFilter(
                ThrottlingFilter.createPostAuthLimiter(0.25, 2, 10.0, 2, fakeNanos::get),
                Duration.ZERO,
                objectMapper);
        UUID wsA = UUID.randomUUID();
        UUID wsB = UUID.randomUUID();
        UUID wsC = UUID.randomUUID();

        // 1. Unauthenticated requests consume 0 global tokens
        for (int i = 0; i < 5; i++) {
            MockHttpServletRequest anonReq = new MockHttpServletRequest(
                    "GET", "/ws/" + wsA + "/scim/v2/ServiceProviderConfig");
            MockHttpServletResponse anonResp = new MockHttpServletResponse();
            postAuthFilter.doFilter(anonReq, anonResp, filterChain);
            assertThat(anonResp.getStatus()).isEqualTo(200);
        }

        // 2. Authenticated wsA and wsB each take 1 token -> drains post-auth global burst of 2
        for (UUID wsId : List.of(wsA, wsB)) {
            MockHttpServletRequest req = new MockHttpServletRequest("GET", "/ws/" + wsId + "/scim/v2/Users");
            req.setAttribute(BearerTokenAuthFilter.AUTHENTICATED_WORKSPACE_ID, wsId);
            MockHttpServletResponse resp = new MockHttpServletResponse();
            postAuthFilter.doFilter(req, resp, filterChain);
            assertThat(resp.getStatus()).isEqualTo(200);
        }

        // 3. Fresh wsC (has 2/2 workspace tokens) tries 2 times while global bucket is empty ->
        //    rejected by post-auth global cap with Retry-After=4, and wsC's workspace bucket is refunded!
        for (int i = 0; i < 2; i++) {
            MockHttpServletRequest blockedReq = new MockHttpServletRequest("GET", "/ws/" + wsC + "/scim/v2/Users");
            blockedReq.setAttribute(BearerTokenAuthFilter.AUTHENTICATED_WORKSPACE_ID, wsC);
            MockHttpServletResponse blockedResp = new MockHttpServletResponse();
            postAuthFilter.doFilter(blockedReq, blockedResp, filterChain);
            assertThat(blockedResp.getStatus()).isEqualTo(429);
            assertThat(blockedResp.getHeader("Retry-After")).isEqualTo("4");
        }

        // 4. Advance clock by 8s (refills global 2 tokens at 0.25 RPS): wsC still has its full 2-token burst!
        fakeNanos.addAndGet(Duration.ofSeconds(8).toNanos());
        for (int i = 0; i < 2; i++) {
            MockHttpServletRequest okReq = new MockHttpServletRequest("GET", "/ws/" + wsC + "/scim/v2/Users");
            okReq.setAttribute(BearerTokenAuthFilter.AUTHENTICATED_WORKSPACE_ID, wsC);
            MockHttpServletResponse okResp = new MockHttpServletResponse();
            postAuthFilter.doFilter(okReq, okResp, filterChain);
            assertThat(okResp.getStatus()).isEqualTo(200);
        }

        // 5. Noisy workspace exceeding its own per-workspace burst is rejected at wsBucket FIRST
        //    without consuming globalBucket permits needed by other workspaces
        AtomicLong noisyClock = new AtomicLong(0L);
        AtomicLong postAuthSleptNanos = new AtomicLong(0L);
        ThrottlingFilter.KeyedPermitLimiter postAuthWithSleep = ThrottlingFilter.createPostAuthLimiter(
                10.0, // global: 1 token per 100ms, burst 3
                3,
                10.0, // per-ws: 1 token per 100ms, burst 1
                1,
                noisyClock::get,
                nanos -> {
                    postAuthSleptNanos.addAndGet(nanos);
                    noisyClock.addAndGet(nanos);
                });
        // wsA uses its 1 burst token, then fails immediate tryAcquire without touching global's remaining 2 tokens
        assertThat(postAuthWithSleep.tryAcquire("ws:" + wsA, Duration.ZERO).allowed()).isTrue();
        assertThat(postAuthWithSleep.tryAcquire("ws:" + wsA, Duration.ZERO).allowed()).isFalse();
        assertThat(postAuthWithSleep.tryAcquire("ws:" + wsB, Duration.ZERO).allowed()).isTrue();
        assertThat(postAuthWithSleep.tryAcquire("ws:" + wsC, Duration.ZERO).allowed()).isTrue();
        // Now global has 0 tokens and wsB has 0 tokens; with 120ms timeout wsB waits 100ms (which refills both!)
        assertThat(postAuthWithSleep.tryAcquire("ws:" + wsB, Duration.ofMillis(120)).allowed()).isTrue();
        assertThat(postAuthSleptNanos.get()).isEqualTo(Duration.ofMillis(100).toNanos());
        // Null/empty key fallback on post-auth limiter works cleanly
        assertThat(postAuthWithSleep.tryAcquire("", Duration.ofMillis(120)).allowed()).isTrue();
    }

    @Test
    void postAuthWorkspaceRateLimitFilter_IsolatesWorkspacesAndSkipsUnauthenticatedRequests() throws Exception {
        AtomicLong fakeNanos = new AtomicLong(0L);
        WorkspaceRateLimitFilter wsFilter = new WorkspaceRateLimitFilter(
                ThrottlingFilter.createKeyedLimiter(0.5, 2, fakeNanos::get),
                Duration.ZERO,
                objectMapper);

        UUID wsA = UUID.randomUUID();
        UUID wsB = UUID.randomUUID();

        // Unauthenticated request (no AUTHENTICATED_WORKSPACE_ID, e.g. anonymous ServiceProviderConfig) passes freely
        for (int i = 0; i < 5; i++) {
            MockHttpServletRequest anon = new MockHttpServletRequest(
                    "GET", "/ws/" + wsA + "/scim/v2/ServiceProviderConfig");
            MockHttpServletResponse anonResp = new MockHttpServletResponse();
            wsFilter.doFilter(anon, anonResp, filterChain);
            assertThat(anonResp.getStatus()).isEqualTo(200);
        }

        // Workspace A consumes its 2-token burst, 3rd gets 429 with Retry-After = ceil(1 / 0.5) = 2
        for (int i = 0; i < 2; i++) {
            MockHttpServletRequest reqA = new MockHttpServletRequest("GET", "/ws/" + wsA + "/scim/v2/Users");
            reqA.setAttribute(BearerTokenAuthFilter.AUTHENTICATED_WORKSPACE_ID, wsA);
            MockHttpServletResponse respA = new MockHttpServletResponse();
            wsFilter.doFilter(reqA, respA, filterChain);
            assertThat(respA.getStatus()).isEqualTo(200);
        }
        MockHttpServletRequest reqA3 = new MockHttpServletRequest("GET", "/ws/" + wsA + "/scim/v2/Users");
        reqA3.setAttribute(BearerTokenAuthFilter.AUTHENTICATED_WORKSPACE_ID, wsA);
        MockHttpServletResponse respA3 = new MockHttpServletResponse();
        wsFilter.doFilter(reqA3, respA3, filterChain);
        assertThat(respA3.getStatus()).isEqualTo(429);
        assertThat(respA3.getHeader("Retry-After")).isEqualTo("2");

        // Workspace B remains unaffected
        MockHttpServletRequest reqB = new MockHttpServletRequest("GET", "/ws/" + wsB + "/scim/v2/Users");
        reqB.setAttribute(BearerTokenAuthFilter.AUTHENTICATED_WORKSPACE_ID, wsB);
        MockHttpServletResponse respB = new MockHttpServletResponse();
        wsFilter.doFilter(reqB, respB, filterChain);
        assertThat(respB.getStatus()).isEqualTo(200);

        // @Autowired constructor works cleanly with property values
        WorkspaceRateLimitFilter springWsFilter = new WorkspaceRateLimitFilter(
                200.0, 0, 0.0, 0, Duration.ZERO, objectMapper);
        MockHttpServletRequest reqSpring = new MockHttpServletRequest("GET", "/ws/" + wsB + "/scim/v2/Users");
        reqSpring.setAttribute(BearerTokenAuthFilter.AUTHENTICATED_WORKSPACE_ID, wsB);
        MockHttpServletResponse respSpring = new MockHttpServletResponse();
        springWsFilter.doFilter(reqSpring, respSpring, filterChain);
        assertThat(respSpring.getStatus()).isEqualTo(200);
    }

    @Test
    void throttlingFilter_TrustedProxyConstructorsAndIpv6Slash64BucketingEnforcedOnDoFilter() throws Exception {
        String scimPath = "/ws/" + UUID.randomUUID() + "/scim/v2/Users";
        List<IpAddressMatcher> explicitProxies = ClientIpResolver.parseTrustedProxies(
                "172.16.0.0/12, 198.51.100.128/25");

        MockHttpServletRequest matchingSlash12 = new MockHttpServletRequest("GET", scimPath);
        matchingSlash12.setRemoteAddr("172.31.255.254");
        matchingSlash12.addHeader("X-Forwarded-For", "203.0.113.9");

        MockHttpServletRequest publicPeer = new MockHttpServletRequest("GET", scimPath);
        publicPeer.setRemoteAddr("198.51.100.99:54321");
        publicPeer.addHeader("CF-Connecting-IP", "203.0.113.1");
        publicPeer.addHeader("X-Forwarded-For", "203.0.113.2");

        ThrottlingFilter explicitProxyFilter = new ThrottlingFilter(
                ThrottlingFilter.createKeyedLimiter(10.0, 2),
                explicitProxies,
                Duration.ZERO,
                objectMapper);
        ThrottlingFilter nullProxyListsFilter = new ThrottlingFilter(
                ThrottlingFilter.createKeyedLimiter(10.0, 2),
                null,
                null,
                Duration.ZERO,
                objectMapper);
        explicitProxyFilter.doFilter(matchingSlash12, new MockHttpServletResponse(), filterChain);
        nullProxyListsFilter.doFilter(publicPeer, new MockHttpServletResponse(), filterChain);

        // IPv6 /64 bucketing prevents interface-ID rotation bypass while isolating distinct /64 prefixes
        AtomicLong v6Clock = new AtomicLong(0L);
        ThrottlingFilter ipv6Filter = new ThrottlingFilter(
                ThrottlingFilter.createPreAuthLimiter(100.0, 20, 10.0, 1, v6Clock::get),
                Duration.ZERO,
                objectMapper);

        MockHttpServletRequest v6FirstHost = new MockHttpServletRequest("GET", scimPath);
        v6FirstHost.setRemoteAddr("2001:db8:cafe:42::1");
        MockHttpServletResponse v6FirstResp = new MockHttpServletResponse();
        ipv6Filter.doFilter(v6FirstHost, v6FirstResp, filterChain);
        assertThat(v6FirstResp.getStatus()).isEqualTo(200);

        // Rotating interface ID within the SAME /64 hits the exhausted bucket -> 429!
        MockHttpServletRequest v6RotatedHostSame64 = new MockHttpServletRequest("GET", scimPath);
        v6RotatedHostSame64.setRemoteAddr("2001:db8:cafe:42:dead:beef:1234:5678");
        MockHttpServletResponse v6RotatedResp = new MockHttpServletResponse();
        ipv6Filter.doFilter(v6RotatedHostSame64, v6RotatedResp, filterChain);
        assertThat(v6RotatedResp.getStatus()).isEqualTo(429);

        // Different /64 subnet gets its own independent bucket -> 200!
        MockHttpServletRequest v6Other64 = new MockHttpServletRequest("GET", scimPath);
        v6Other64.setRemoteAddr("2001:db8:cafe:43::1");
        MockHttpServletResponse v6OtherResp = new MockHttpServletResponse();
        ipv6Filter.doFilter(v6Other64, v6OtherResp, filterChain);
        assertThat(v6OtherResp.getStatus()).isEqualTo(200);
    }

    @Test
    void waitTimeoutPositive_WaitsWhenWithinBudgetFailsFastWhenExceedingAndHandlesInterruption() throws Exception {
        AtomicLong fakeNanos = new AtomicLong(0L);
        AtomicLong totalSleptNanos = new AtomicLong(0L);
        ThrottlingFilter.KeyedPermitLimiter limiter = ThrottlingFilter.createPreAuthLimiter(
                100.0,
                10,
                10.0, // 1 token per 100ms
                1,
                fakeNanos::get,
                nanos -> {
                    totalSleptNanos.addAndGet(nanos);
                    fakeNanos.addAndGet(nanos);
                });
        ThrottlingFilter filter = new ThrottlingFilter(limiter, Duration.ofMillis(150), objectMapper);
        String path = "/ws/" + UUID.randomUUID() + "/scim/v2/Users";

        // 1st request consumes initial burst token with 0 sleep
        MockHttpServletResponse resp1 = new MockHttpServletResponse();
        filter.doFilter(new MockHttpServletRequest("GET", path), resp1, filterChain);
        assertThat(resp1.getStatus()).isEqualTo(200);
        assertThat(totalSleptNanos.get()).isZero();

        // 2nd request needs 100ms <= 150ms waitTimeout -> waits 100ms and succeeds
        MockHttpServletResponse resp2 = new MockHttpServletResponse();
        filter.doFilter(new MockHttpServletRequest("GET", path), resp2, filterChain);
        assertThat(resp2.getStatus()).isEqualTo(200);
        assertThat(totalSleptNanos.get()).isEqualTo(Duration.ofMillis(100).toNanos());

        // Tight 50ms timeout filter on same limiter: needs 100ms > 50ms -> fails fast without sleeping!
        ThrottlingFilter tightFilter = new ThrottlingFilter(limiter, Duration.ofMillis(50), objectMapper);
        long sleptBeforeTight = totalSleptNanos.get();
        MockHttpServletResponse resp3 = new MockHttpServletResponse();
        tightFilter.doFilter(new MockHttpServletRequest("GET", path), resp3, filterChain);
        assertThat(resp3.getStatus()).isEqualTo(429);
        assertThat(totalSleptNanos.get()).isEqualTo(sleptBeforeTight);

        // Interruption during sleep restores Thread interrupt flag, refunds reserved token, and returns 429
        AtomicBoolean shouldInterrupt = new AtomicBoolean(true);
        AtomicLong interruptClock = new AtomicLong(0L);
        ThrottlingFilter.KeyedPermitLimiter interruptibleLimiter = ThrottlingFilter.createKeyedLimiter(
                10.0,
                1,
                interruptClock::get,
                nanos -> {
                    if (shouldInterrupt.get()) {
                        throw new InterruptedException("simulated interrupt");
                    }
                    interruptClock.addAndGet(nanos);
                });
        ThrottlingFilter interruptFilter = new ThrottlingFilter(
                interruptibleLimiter, Duration.ofMillis(200), objectMapper);

        interruptFilter.doFilter(new MockHttpServletRequest("GET", path), new MockHttpServletResponse(), filterChain);

        try {
            MockHttpServletResponse interruptedResp = new MockHttpServletResponse();
            interruptFilter.doFilter(new MockHttpServletRequest("GET", path), interruptedResp, filterChain);
            assertThat(interruptedResp.getStatus()).isEqualTo(429);
            assertThat(Thread.currentThread().isInterrupted()).isTrue();
        } finally {
            Thread.interrupted();
        }

        shouldInterrupt.set(false);
        MockHttpServletResponse recoveredResp = new MockHttpServletResponse();
        ThrottlingFilter postInterruptFilter = new ThrottlingFilter(
                interruptibleLimiter, Duration.ofMillis(100), objectMapper);
        postInterruptFilter.doFilter(new MockHttpServletRequest("GET", path), recoveredResp, filterChain);
        assertThat(recoveredResp.getStatus()).isEqualTo(200);
    }

    @Test
    void prodConfig1000RpsAndBundled200Rps_MultiIpFloodsLeaveColdTenantsEntraId40MinAndScimValidatorOk() throws Exception {
        AtomicLong fakeNanos = new AtomicLong(Duration.ofSeconds(1).toNanos());

        // Exact K8s production config: requests-per-second=1000, all sub-limits 0 (default):
        // - ThrottlingFilter per-IP = 250 RPS / 250 burst
        // - UnauthenticatedLookupLimiter pod-wide = 1000 RPS / 1000 burst; per-IP failed lookup = 15.625 RPS / 16 burst (1/64)
        // - verifiedTokenHashes TTL = 24 hours, maxSize = 50,000
        // - Post-auth global = 1000 RPS / 1000 burst; per-workspace = 250 RPS / 250 burst
        MockEnvironment prodEnv = new MockEnvironment()
                .withProperty("app.rate-limit.enabled", "true")
                .withProperty("app.rate-limit.requests-per-second", "1000");

        ThrottlingFilter preAuthFilter = new ThrottlingFilter(
                ThrottlingFilter.createPreAuthLimiter(1000.0, 0, 0.0, 0, fakeNanos::get),
                Duration.ZERO,
                objectMapper);
        ThrottlingFilter.UnauthenticatedLookupLimiter unauthLookupLimiter =
                ThrottlingFilter.createUnauthenticatedLookupLimiter(prodEnv, fakeNanos::get);
        WorkspaceRateLimitFilter postAuthWsFilter = new WorkspaceRateLimitFilter(
                ThrottlingFilter.createPostAuthLimiter(1000.0, 0, 0.0, 0, fakeNanos::get),
                Duration.ZERO,
                objectMapper);

        record TenantFixture(UUID workspaceId, String rawToken, String clientIp) {}
        List<TenantFixture> tenants = new ArrayList<>(92);
        Map<String, WorkspaceToken> tokenByHash = new HashMap<>(128);
        for (int i = 0; i < 92; i++) {
            UUID wsId = UUID.randomUUID();
            Workspace ws = new Workspace();
            ws.setId(wsId);
            ws.setCreatedByUsername("entra-tenant-" + i);

            String rawToken = "entra-valid-token-" + i;
            String tokenHash = TokenSecurityUtil.sha256Hex(rawToken);
            WorkspaceToken tokenEntity = new WorkspaceToken();
            tokenEntity.setWorkspace(ws);
            tokenEntity.setTokenHash(tokenHash);
            tokenEntity.setExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS));

            tenants.add(new TenantFixture(wsId, rawToken, "198.51.100." + (i + 1)));
            tokenByHash.put(tokenHash, tokenEntity);
        }

        WorkspaceTokenRepository tokenRepository = Mockito.mock(WorkspaceTokenRepository.class);
        when(tokenRepository.findByTokenHashAndNotRevoked(anyString())).thenAnswer(inv -> {
            String hash = inv.getArgument(0);
            return Optional.ofNullable(tokenByHash.get(hash));
        });
        WorkspaceRepository workspaceRepository = Mockito.mock(WorkspaceRepository.class);
        when(workspaceRepository.existsById(Mockito.any())).thenReturn(true);
        BearerTokenAuthFilter bearerFilter = new BearerTokenAuthFilter(
                tokenRepository, workspaceRepository, objectMapper, unauthLookupLimiter);

        FilterChain fullChain = (req, res) -> preAuthFilter.doFilter(
                req, res, (r2, s2) -> bearerFilter.doFilter(
                        r2, s2, (r3, s3) -> postAuthWsFilter.doFilter(r3, s3, filterChain)));

        UUID targetWsId = tenants.getFirst().workspaceId();

        // 1. Reviewer's Round 6 scenario at t = 0: 4 attacker IPs x 100 bad-token requests (400 total):
        //    - Each IP gets ONLY 16 lookups (4 x 16 = 64 401s; 936/1,000 [93.6%] pod permits remain free!)
        //    - Remaining 84 per IP (336 total) get 429 with 0 DB queries!
        int fourIp401 = 0;
        int fourIp429 = 0;
        for (int ipIdx = 1; ipIdx <= 4; ipIdx++) {
            String attackerIp = "203.0.113." + ipIdx;
            for (int reqNum = 1; reqNum <= 100; reqNum++) {
                MockHttpServletRequest junkReq = new MockHttpServletRequest(
                        "GET", "/ws/" + targetWsId + "/scim/v2/Users");
                junkReq.setRemoteAddr(attackerIp);
                junkReq.addHeader("Authorization", "Bearer four-ip-junk-" + ipIdx + "-" + reqNum);
                MockHttpServletResponse junkResp = new MockHttpServletResponse();
                fullChain.doFilter(junkReq, junkResp);

                if (reqNum <= 16) {
                    assertThat(junkResp.getStatus()).isEqualTo(401);
                    fourIp401++;
                } else {
                    assertThat(junkResp.getStatus()).isEqualTo(429);
                    assertThat(junkReq.getAttribute(ScimRequestMetricAttributes.THROTTLED))
                            .isEqualTo(ScimRequestMetricAttributes.THROTTLED_YES);
                    fourIp429++;
                }
            }
        }
        assertThat(fourIp401).isEqualTo(64);
        assertThat(fourIp429).isEqualTo(336);
        verify(tokenRepository, times(64)).findByTokenHashAndNotRevoked(anyString());

        // Single-IP 300-request check on 203.0.113.1 (requests 101..250 hit perIpLookupBucket 429;
        // requests 251..300 hit ThrottlingFilter 250 per-IP cap 429; 0 DB queries across all 200):
        Mockito.clearInvocations(tokenRepository);
        for (int reqNum = 101; reqNum <= 300; reqNum++) {
            MockHttpServletRequest extraJunk = new MockHttpServletRequest(
                    "GET", "/ws/" + targetWsId + "/scim/v2/Users");
            extraJunk.setRemoteAddr("203.0.113.1");
            extraJunk.addHeader("Authorization", "Bearer extra-junk-" + reqNum);
            MockHttpServletResponse extraResp = new MockHttpServletResponse();
            fullChain.doFilter(extraJunk, extraResp);
            assertThat(extraResp.getStatus()).isEqualTo(429);
        }
        verifyNoInteractions(tokenRepository);

        // Immediately at t = 0 during the 4-IP flood: a cold 5th IP + 90 cold uncached tenant IPs (91 cold tenants,
        // simulating a newly rolled-out pod during a 2-pod K8s deploy) ALL return 200 OK and refund their permits!
        for (int i = 0; i < 91; i++) {
            TenantFixture tenant = tenants.get(i);
            MockHttpServletRequest tenantReq = new MockHttpServletRequest(
                    "GET", "/ws/" + tenant.workspaceId() + "/scim/v2/Users");
            tenantReq.setRemoteAddr(tenant.clientIp());
            tenantReq.addHeader("Authorization", "Bearer " + tenant.rawToken());
            MockHttpServletResponse tenantResp = new MockHttpServletResponse();
            fullChain.doFilter(tenantReq, tenantResp);
            assertThat(tenantResp.getStatus()).isEqualTo(200);
        }
        verify(tokenRepository, times(91)).findByTokenHashAndNotRevoked(anyString());

        // 2. Scale flood to 32 attacker IPs x 100 bad-token requests (28 more IPs = 3,200 total bad-token requests!):
        //    28 x 16 = 448 more 401s (total 512 / 1,000 pod permits used, leaving 488 free!) ->
        //    cold tenant #92 STILL authenticates with 200 OK!
        int moreIp401 = 0;
        int moreIp429 = 0;
        for (int ipIdx = 5; ipIdx <= 32; ipIdx++) {
            String attackerIp = "203.0.113." + ipIdx;
            for (int reqNum = 1; reqNum <= 100; reqNum++) {
                MockHttpServletRequest junkReq = new MockHttpServletRequest(
                        "GET", "/ws/" + targetWsId + "/scim/v2/Users");
                junkReq.setRemoteAddr(attackerIp);
                junkReq.addHeader("Authorization", "Bearer flood32-" + ipIdx + "-" + reqNum);
                MockHttpServletResponse junkResp = new MockHttpServletResponse();
                fullChain.doFilter(junkReq, junkResp);
                if (junkResp.getStatus() == 401) {
                    moreIp401++;
                } else if (junkResp.getStatus() == 429) {
                    moreIp429++;
                }
            }
        }
        assertThat(moreIp401).isEqualTo(448);
        assertThat(moreIp429).isEqualTo(2352);

        TenantFixture tenant92 = tenants.get(91);
        MockHttpServletRequest tenant92Req = new MockHttpServletRequest(
                "GET", "/ws/" + tenant92.workspaceId() + "/scim/v2/Users");
        tenant92Req.setRemoteAddr(tenant92.clientIp());
        tenant92Req.addHeader("Authorization", "Bearer " + tenant92.rawToken());
        MockHttpServletResponse tenant92Resp = new MockHttpServletResponse();
        fullChain.doFilter(tenant92Req, tenant92Resp);
        assertThat(tenant92Resp.getStatus()).isEqualTo(200);

        // 3. Advance fakeNanos by 40 minutes (Entra ID's ~40-minute sync cycle!),
        //    drain all 1,000 podLookupBucket permits to 0 across 64 botnet IPs (64 x 16 = 1,024 junk requests:
        //    first 1,000 -> 401; remaining 24 -> 429), then have ALL 92 Entra ID tenants sync again -> ALL 92 / 92 200 OK!
        fakeNanos.addAndGet(Duration.ofMinutes(40).toNanos());
        int botnet401 = 0;
        int botnet429 = 0;
        for (int ipIdx = 1; ipIdx <= 64; ipIdx++) {
            for (int j = 1; j <= 16; j++) {
                MockHttpServletRequest botReq = new MockHttpServletRequest(
                        "GET", "/ws/" + targetWsId + "/scim/v2/Users");
                botReq.setRemoteAddr("198.18.1." + ipIdx);
                botReq.addHeader("Authorization", "Bearer botnet-40m-" + ipIdx + "-" + j);
                MockHttpServletResponse botResp = new MockHttpServletResponse();
                fullChain.doFilter(botReq, botResp);
                if (botResp.getStatus() == 401) {
                    botnet401++;
                } else if (botResp.getStatus() == 429) {
                    botnet429++;
                }
            }
        }
        assertThat(botnet401).isEqualTo(1000);
        assertThat(botnet429).isEqualTo(24);

        Mockito.clearInvocations(tokenRepository);
        for (TenantFixture tenant : tenants) {
            MockHttpServletRequest syncReq = new MockHttpServletRequest(
                    "GET", "/ws/" + tenant.workspaceId() + "/scim/v2/Users");
            syncReq.setRemoteAddr(tenant.clientIp());
            syncReq.addHeader("Authorization", "Bearer " + tenant.rawToken());
            MockHttpServletResponse syncResp = new MockHttpServletResponse();
            fullChain.doFilter(syncReq, syncResp);
            assertThat(syncResp.getStatus()).isEqualTo(200);
        }
        verify(tokenRepository, times(92)).findByTokenHashAndNotRevoked(anyString());

        // 4. Advance fakeNanos by 24 hours + 1 minute (> VERIFIED_TOKEN_IDLE_EXPIRATION),
        //    drain all 1,000 podLookupBucket permits across 63 botnet IPs (63 x 16 = 1,008: 1,000 401s + 8 429s),
        //    then verify an idle tenant's 24h entry expired so its cold lookup hits 429 with 0 DB queries!
        fakeNanos.addAndGet(Duration.ofHours(24).plusMinutes(1).toNanos());
        int drain24h401 = 0;
        int drain24h429 = 0;
        for (int ipIdx = 1; ipIdx <= 63; ipIdx++) {
            for (int j = 1; j <= 16; j++) {
                MockHttpServletRequest drainReq = new MockHttpServletRequest(
                        "GET", "/ws/" + targetWsId + "/scim/v2/Users");
                drainReq.setRemoteAddr("198.18.2." + ipIdx);
                drainReq.addHeader("Authorization", "Bearer botnet-24h-" + ipIdx + "-" + j);
                MockHttpServletResponse drainResp = new MockHttpServletResponse();
                fullChain.doFilter(drainReq, drainResp);
                if (drainResp.getStatus() == 401) {
                    drain24h401++;
                } else if (drainResp.getStatus() == 429) {
                    drain24h429++;
                }
            }
        }
        assertThat(drain24h401).isEqualTo(1000);
        assertThat(drain24h429).isEqualTo(8);

        Mockito.clearInvocations(tokenRepository);
        TenantFixture expiredHintTenant = tenants.getFirst();
        assertThat(unauthLookupLimiter.isKnownActiveToken(
                expiredHintTenant.workspaceId() + ":" + TokenSecurityUtil.sha256Hex(expiredHintTenant.rawToken())))
                .isFalse();

        MockHttpServletRequest coldAfter24hReq = new MockHttpServletRequest(
                "GET", "/ws/" + expiredHintTenant.workspaceId() + "/scim/v2/Users");
        coldAfter24hReq.setRemoteAddr(expiredHintTenant.clientIp());
        coldAfter24hReq.addHeader("Authorization", "Bearer " + expiredHintTenant.rawToken());
        MockHttpServletResponse coldAfter24hResp = new MockHttpServletResponse();
        fullChain.doFilter(coldAfter24hReq, coldAfter24hResp);
        assertThat(coldAfter24hResp.getStatus()).isEqualTo(429);
        verifyNoInteractions(tokenRepository);

        // 5. Bundled 200 RPS scim-validator (Rfc7644AuthSpec.groovy) + 4-IP flood check in 0 ns elapsed:
        //    podLimit = 200 RPS / 200 burst, perIpLimit = 3.125 RPS (1/64) / 12 burst:
        //    - 10 rapid invalid-token + anonymous ServiceProviderConfig probes from 127.0.0.1 in 0 ns ALL get 401/200!
        //    - Probes 11..12 get 401; probe 13 gets 429!
        //    - 3 more attacker IPs x 50 bad tokens only use 3 x 12 = 36 permits (48 / 200 total across 4 IPs, 152 free!)
        //    - Cold valid tenant from a 5th IP gets 200 OK!
        AtomicLong validatorClock = new AtomicLong(Duration.ofSeconds(1).toNanos());
        MockEnvironment bundledEnv = new MockEnvironment()
                .withProperty("app.rate-limit.enabled", "true")
                .withProperty("app.rate-limit.requests-per-second", "200");
        ThrottlingFilter bundledPreAuth = new ThrottlingFilter(
                ThrottlingFilter.createPreAuthLimiter(200.0, 0, 0.0, 0, validatorClock::get),
                Duration.ZERO,
                objectMapper);
        ThrottlingFilter.UnauthenticatedLookupLimiter bundledLookupLimiter =
                ThrottlingFilter.createUnauthenticatedLookupLimiter(bundledEnv, validatorClock::get);
        BearerTokenAuthFilter bundledBearer = new BearerTokenAuthFilter(
                tokenRepository, workspaceRepository, objectMapper, bundledLookupLimiter);
        FilterChain bundledChain = (req, res) -> bundledPreAuth.doFilter(
                req, res, (r2, s2) -> bundledBearer.doFilter(r2, s2, filterChain));

        for (int probe = 1; probe <= 8; probe++) {
            MockHttpServletRequest badTokenReq = new MockHttpServletRequest(
                    "GET", "/ws/" + targetWsId + "/scim/v2/Users");
            badTokenReq.setRemoteAddr("127.0.0.1");
            badTokenReq.addHeader("Authorization", "Bearer validator-invalid-" + probe);
            MockHttpServletResponse badTokenResp = new MockHttpServletResponse();
            bundledChain.doFilter(badTokenReq, badTokenResp);
            assertThat(badTokenResp.getStatus()).isEqualTo(401);
        }
        for (int spc = 1; spc <= 2; spc++) {
            MockHttpServletRequest anonSpcReq = new MockHttpServletRequest(
                    "GET", "/ws/" + targetWsId + "/scim/v2/ServiceProviderConfig");
            anonSpcReq.setRemoteAddr("127.0.0.1");
            MockHttpServletResponse anonSpcResp = new MockHttpServletResponse();
            bundledChain.doFilter(anonSpcReq, anonSpcResp);
            assertThat(anonSpcResp.getStatus()).isEqualTo(200);
        }
        for (int probe = 11; probe <= 12; probe++) {
            MockHttpServletRequest badTokenReq = new MockHttpServletRequest(
                    "GET", "/ws/" + targetWsId + "/scim/v2/Users");
            badTokenReq.setRemoteAddr("127.0.0.1");
            badTokenReq.addHeader("Authorization", "Bearer validator-invalid-" + probe);
            MockHttpServletResponse badTokenResp = new MockHttpServletResponse();
            bundledChain.doFilter(badTokenReq, badTokenResp);
            assertThat(badTokenResp.getStatus()).isEqualTo(401);
        }
        MockHttpServletRequest probe13Req = new MockHttpServletRequest(
                "GET", "/ws/" + targetWsId + "/scim/v2/Users");
        probe13Req.setRemoteAddr("127.0.0.1");
        probe13Req.addHeader("Authorization", "Bearer validator-invalid-13");
        MockHttpServletResponse probe13Resp = new MockHttpServletResponse();
        bundledChain.doFilter(probe13Req, probe13Resp);
        assertThat(probe13Resp.getStatus()).isEqualTo(429);

        int bundledFlood401 = 0;
        int bundledFlood429 = 0;
        for (int ipIdx = 2; ipIdx <= 4; ipIdx++) {
            for (int j = 1; j <= 50; j++) {
                MockHttpServletRequest bFloodReq = new MockHttpServletRequest(
                        "GET", "/ws/" + targetWsId + "/scim/v2/Users");
                bFloodReq.setRemoteAddr("203.0.114." + ipIdx);
                bFloodReq.addHeader("Authorization", "Bearer bundled-flood-" + ipIdx + "-" + j);
                MockHttpServletResponse bFloodResp = new MockHttpServletResponse();
                bundledChain.doFilter(bFloodReq, bFloodResp);
                if (bFloodResp.getStatus() == 401) {
                    bundledFlood401++;
                } else if (bFloodResp.getStatus() == 429) {
                    bundledFlood429++;
                }
            }
        }
        assertThat(bundledFlood401).isEqualTo(36);
        assertThat(bundledFlood429).isEqualTo(114);

        // Cold valid tenant from a 5th IP still has 152/200 pod lookup permits free -> 200 OK!
        TenantFixture coldBundledTenant = tenants.get(1);
        MockHttpServletRequest coldBundledReq = new MockHttpServletRequest(
                "GET", "/ws/" + coldBundledTenant.workspaceId() + "/scim/v2/Users");
        coldBundledReq.setRemoteAddr(coldBundledTenant.clientIp());
        coldBundledReq.addHeader("Authorization", "Bearer " + coldBundledTenant.rawToken());
        MockHttpServletResponse coldBundledResp = new MockHttpServletResponse();
        bundledChain.doFilter(coldBundledReq, coldBundledResp);
        assertThat(coldBundledResp.getStatus()).isEqualTo(200);
    }

    @Test
    void subRateLimitDefaultsOverridesAndAutowiredConstructors_BehaveAccurately() throws Exception {
        assertThat(ThrottlingFilter.resolveBurst(0.5, 0)).isEqualTo(1);
        assertThat(ThrottlingFilter.resolveBurst(200.0, 0)).isEqualTo(200);
        assertThat(ThrottlingFilter.resolveBurst(200.4, -5)).isEqualTo(201);
        assertThat(ThrottlingFilter.resolveBurst(5000.0, 0)).isEqualTo(ThrottlingFilter.MAX_DEFAULT_BURST);
        assertThat(ThrottlingFilter.resolveBurst(200.0, 25)).isEqualTo(25);

        // Sub-rate-limit defaults (Tier 1 per-IP & Tier 2 per-workspace): parentRPS / 4.0 and ceil(resolvedParentBurst / 4.0)
        assertThat(ThrottlingFilter.resolveSubRateLimit(100.0, 0, 0.0, 0))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(25.0, 25));
        assertThat(ThrottlingFilter.resolveSubRateLimit(1000.0, 0, 0.0, 0))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(250.0, 250));
        assertThat(ThrottlingFilter.resolveSubRateLimit(10000.0, 0, 0.0, 0))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(2500.0, 250));
        assertThat(ThrottlingFilter.resolveSubRateLimit(0.2, 10, 0.0, 0))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(0.05, 3));
        // Explicit subRPS > 0 with subBurst = 0 uses resolveBurst(subRPS, 0)
        assertThat(ThrottlingFilter.resolveSubRateLimit(200.0, 200, 15.2, 0))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(15.2, 16));
        // Explicit subBurst > 0 overrides while keeping default globalRPS / 4.0
        assertThat(ThrottlingFilter.resolveSubRateLimit(200.0, 200, 0.0, 42))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(50.0, 42));

        // Pod-wide unauthenticated lookup limit defaults (1x global) and explicit overrides
        assertThat(ThrottlingFilter.resolvePodLookupLimit(1000.0, 0, 0.0, 0))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(1000.0, 1000));
        assertThat(ThrottlingFilter.resolvePodLookupLimit(200.0, 0, 0.0, 0))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(200.0, 200));
        assertThat(ThrottlingFilter.resolvePodLookupLimit(4000.0, 4000, 0.0, 0))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(4000.0, 4000));
        assertThat(ThrottlingFilter.resolvePodLookupLimit(200.0, 200, 15.2, 0))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(15.2, 16));
        assertThat(ThrottlingFilter.resolvePodLookupLimit(200.0, 200, 0.0, 42))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(200.0, 42));
        assertThat(ThrottlingFilter.resolvePodLookupLimit(200.0, 200, 0.5, 2))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(0.5, 2));

        // Per-IP unauthenticated lookup limit defaults (1/64 RPS, min(ceil(podBurst/16), max(12, ceil(podBurst/64))))
        assertThat(ThrottlingFilter.resolvePerIpLookupLimit(
                new ThrottlingFilter.SubRateLimit(1000.0, 1000), 0.0, 0))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(15.625, 16));
        assertThat(ThrottlingFilter.resolvePerIpLookupLimit(
                new ThrottlingFilter.SubRateLimit(200.0, 200), 0.0, 0))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(3.125, 12));
        assertThat(ThrottlingFilter.resolvePerIpLookupLimit(
                new ThrottlingFilter.SubRateLimit(4000.0, 4000), 0.0, 0))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(62.5, 63));
        assertThat(ThrottlingFilter.resolvePerIpLookupLimit(
                new ThrottlingFilter.SubRateLimit(0.5, 2), 0.0, 0))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(0.0078125, 1));
        assertThat(ThrottlingFilter.resolvePerIpLookupLimit(
                new ThrottlingFilter.SubRateLimit(200.0, 200), 4.2, 0))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(4.2, 5));
        assertThat(ThrottlingFilter.resolvePerIpLookupLimit(
                new ThrottlingFilter.SubRateLimit(200.0, 200), 0.0, 7))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(3.125, 7));
        assertThat(ThrottlingFilter.resolvePerIpLookupLimit(
                new ThrottlingFilter.SubRateLimit(200.0, 200), 0.25, 2))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(0.25, 2));

        assertThatThrownBy(() -> ThrottlingFilter.createPreAuthLimiter(0.0, 10, 0.0, 0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ThrottlingFilter.createPreAuthLimiter(-1.0, 10, 0.0, 0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ThrottlingFilter.createPreAuthLimiter(Double.NaN, 10, 0.0, 0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ThrottlingFilter.createPreAuthLimiter(10.0, 10, Double.POSITIVE_INFINITY, 0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ThrottlingFilter.resolvePodLookupLimit(0.0, 10, 0.0, 0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ThrottlingFilter.resolvePodLookupLimit(100.0, 10, Double.NaN, 0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ThrottlingFilter.resolvePerIpLookupLimit(null, 0.0, 0))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> ThrottlingFilter.resolvePerIpLookupLimit(
                new ThrottlingFilter.SubRateLimit(0.0, 10), 0.0, 0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ThrottlingFilter.resolvePerIpLookupLimit(
                new ThrottlingFilter.SubRateLimit(100.0, 100), Double.NEGATIVE_INFINITY, 0))
                .isInstanceOf(IllegalArgumentException.class);

        // Verify UnauthenticatedLookupLimiter.NOOP and public factories + null/attribute/timeout branches
        assertThat(ThrottlingFilter.UnauthenticatedLookupLimiter.NOOP.isKnownActiveToken("ws:hash")).isFalse();
        assertThat(ThrottlingFilter.UnauthenticatedLookupLimiter.NOOP.tryAcquireLookupPermit(null).allowed()).isTrue();
        ThrottlingFilter.UnauthenticatedLookupLimiter.NOOP.onValidTokenLookup(null, "ws:hash", true);
        ThrottlingFilter.UnauthenticatedLookupLimiter.NOOP.evictToken("ws:hash");

        ThrottlingFilter.UnauthenticatedLookupLimiter defaultLookupLimiter =
                ThrottlingFilter.createUnauthenticatedLookupLimiter(200.0, 0, 0.0, 0, 0.0, 0, Duration.ZERO);
        assertThat(defaultLookupLimiter.isKnownActiveToken(null)).isFalse();
        assertThat(defaultLookupLimiter.tryAcquireLookupPermit(null).allowed()).isTrue();
        defaultLookupLimiter.onValidTokenLookup(null, null, false);
        defaultLookupLimiter.evictToken(null);

        // Falsifiable test for ipBucket.refund() on podLookupBucket rejection AND ipBucket == null in onValidTokenLookup:
        // perIpLimit = (0.1 RPS -> 10s refill, burst 1), podLimit = (10.0 RPS -> 100ms refill, burst 1)
        AtomicLong refundClock = new AtomicLong(Duration.ofSeconds(1).toNanos());
        ThrottlingFilter.UnauthenticatedLookupLimiter refundVerifyLimiter =
                ThrottlingFilter.createUnauthenticatedLookupLimiter(
                        new ThrottlingFilter.SubRateLimit(10.0, 1),
                        new ThrottlingFilter.SubRateLimit(0.1, 1),
                        Duration.ZERO,
                        refundClock::get);
        MockHttpServletRequest ip1Req = new MockHttpServletRequest("GET", "/ws/" + UUID.randomUUID() + "/scim/v2/Users");
        ip1Req.setRemoteAddr("198.51.100.210");
        MockHttpServletRequest ip2Req = new MockHttpServletRequest("GET", "/ws/" + UUID.randomUUID() + "/scim/v2/Users");
        ip2Req.setRemoteAddr("198.51.100.211");

        // IP1 drains podLookupBucket (1 -> 0); IP2 acquires ipBucket (1 -> 0), fails podLookupBucket, and refunds ipBucket (0 -> 1)!
        assertThat(refundVerifyLimiter.tryAcquireLookupPermit(ip1Req).allowed()).isTrue();
        assertThat(refundVerifyLimiter.tryAcquireLookupPermit(ip2Req).allowed()).isFalse();

        // Advance only 100ms: podLookupBucket refills 1.0 token, whereas ip2's 0.1 RPS bucket would only refill 0.01 without refund!
        refundClock.addAndGet(Duration.ofMillis(100).toNanos());
        assertThat(refundVerifyLimiter.tryAcquireLookupPermit(ip2Req).allowed()).isTrue();

        // Cover ipBucket == null branch in onValidTokenLookup when perIpLookupBuckets has no cached entry for unseen IP
        MockHttpServletRequest unseenIpReq = new MockHttpServletRequest("GET", "/ws/" + UUID.randomUUID() + "/scim/v2/Users");
        unseenIpReq.setRemoteAddr("198.51.100.212");
        refundVerifyLimiter.onValidTokenLookup(unseenIpReq, "ws:unseen-ip-hash", true);
        assertThat(refundVerifyLimiter.isKnownActiveToken("ws:unseen-ip-hash")).isTrue();

        // Verify Environment factory with explicit proxies + waitTimeout + blank cached attribute fallback
        AtomicLong lookupSleepClock = new AtomicLong(Duration.ofSeconds(1).toNanos());
        AtomicLong lookupSleptNanos = new AtomicLong(0L);
        ThrottlingFilter.UnauthenticatedLookupLimiter sleepingLookupLimiter =
                ThrottlingFilter.createUnauthenticatedLookupLimiter(
                        new ThrottlingFilter.SubRateLimit(10.0, 1),
                        new ThrottlingFilter.SubRateLimit(10.0, 2),
                        null,
                        null,
                        Duration.ofMillis(120),
                        lookupSleepClock::get,
                        nanos -> {
                            lookupSleptNanos.addAndGet(nanos);
                            lookupSleepClock.addAndGet(nanos);
                        });
        MockHttpServletRequest blankAttrReq = new MockHttpServletRequest("GET", "/ws/" + UUID.randomUUID() + "/scim/v2/Users");
        blankAttrReq.setRemoteAddr("198.51.100.200");
        blankAttrReq.setAttribute(ThrottlingFilter.RESOLVED_CLIENT_IP_KEY_ATTRIBUTE, "");
        assertThat(sleepingLookupLimiter.tryAcquireLookupPermit(blankAttrReq).allowed()).isTrue();
        assertThat(blankAttrReq.getAttribute(ThrottlingFilter.RESOLVED_CLIENT_IP_KEY_ATTRIBUTE))
                .isEqualTo("ip:198.51.100.200");
        // 2nd acquire from same IP passes perIp (1 left) and sleeps 100ms <= 120ms on podLookupBucket!
        assertThat(sleepingLookupLimiter.tryAcquireLookupPermit(blankAttrReq).allowed()).isTrue();
        assertThat(lookupSleptNanos.get()).isEqualTo(Duration.ofMillis(100).toNanos());

        MockEnvironment customEnv = new MockEnvironment()
                .withProperty("app.rate-limit.trusted-proxies", "10.0.0.0/8")
                .withProperty("app.rate-limit.trusted-cloudflare-proxies", "173.245.48.0/20");
        ThrottlingFilter.UnauthenticatedLookupLimiter envLimiter =
                ThrottlingFilter.createUnauthenticatedLookupLimiter(customEnv);
        MockHttpServletRequest envReq = new MockHttpServletRequest("GET", "/ws/" + UUID.randomUUID() + "/scim/v2/Users");
        envReq.setRemoteAddr("173.245.48.5");
        envReq.addHeader("CF-Connecting-IP", "203.0.113.55");
        assertThat(envLimiter.tryAcquireLookupPermit(envReq).allowed()).isTrue();
        assertThat(envReq.getAttribute(ThrottlingFilter.RESOLVED_CLIENT_IP_KEY_ATTRIBUTE))
                .isEqualTo("ip:203.0.113.55");

        // Verify relaxed uppercase-underscore SystemEnvironmentPropertySource binding via StandardEnvironment
        StandardEnvironment sysEnv = new StandardEnvironment();
        sysEnv.getPropertySources().addFirst(new SystemEnvironmentPropertySource(
                StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                Map.of(
                        "APP_RATE_LIMIT_REQUESTS_PER_SECOND", "100",
                        "APP_RATE_LIMIT_PER_IP_UNAUTHENTICATED_REQUESTS_PER_SECOND", "0.25",
                        "APP_RATE_LIMIT_PER_IP_UNAUTHENTICATED_BURST", "2",
                        "APP_RATE_LIMIT_WAIT_TIMEOUT", "50ms"
                )));
        ThrottlingFilter.UnauthenticatedLookupLimiter sysEnvLimiter =
                ThrottlingFilter.createUnauthenticatedLookupLimiter(sysEnv);
        MockHttpServletRequest sysEnvReq = new MockHttpServletRequest("GET", "/ws/" + UUID.randomUUID() + "/scim/v2/Users");
        sysEnvReq.setRemoteAddr("198.51.100.220");
        assertThat(sysEnvLimiter.tryAcquireLookupPermit(sysEnvReq).allowed()).isTrue();
        assertThat(sysEnvLimiter.tryAcquireLookupPermit(sysEnvReq).allowed()).isTrue();
        // 3rd request needs 4000ms (> 50ms wait-timeout) -> fails fast without sleeping with Retry-After = 4!
        ThrottlingFilter.AcquireResult sysEnvRejected = sysEnvLimiter.tryAcquireLookupPermit(sysEnvReq);
        assertThat(sysEnvRejected.allowed()).isFalse();
        assertThat(sysEnvRejected.retryAfterSeconds()).isEqualTo(4L);

        ObjectProvider<ThrottlingFilter.KeyedPermitLimiter> emptyProvider = emptyObjectProvider();
        ThrottlingFilter defaultSpringFilter = new ThrottlingFilter(
                50.0, 0, 0.0, 0, "", "", Duration.ZERO, emptyProvider, objectMapper);
        MockHttpServletResponse okResp = new MockHttpServletResponse();
        defaultSpringFilter.doFilter(
                new MockHttpServletRequest("GET", "/ws/" + UUID.randomUUID() + "/scim/v2/Users"),
                okResp,
                filterChain);
        assertThat(okResp.getStatus()).isEqualTo(200);

        AtomicInteger customCalls = new AtomicInteger();
        ObjectProvider<ThrottlingFilter.KeyedPermitLimiter> customProvider = singletonObjectProvider((_, _) -> {
            customCalls.incrementAndGet();
            return ThrottlingFilter.AcquireResult.ALLOWED;
        });
        ThrottlingFilter customSpringFilter = new ThrottlingFilter(
                50.0, 0, 0.0, 0, "127.0.0.1/8", "173.245.48.0/20", Duration.ZERO, customProvider, objectMapper);
        customSpringFilter.doFilter(
                new MockHttpServletRequest("GET", "/ws/" + UUID.randomUUID() + "/scim/v2/Users"),
                new MockHttpServletResponse(),
                filterChain);
        assertThat(customCalls.get()).isEqualTo(1);
    }

    private static <T> ObjectProvider<T> emptyObjectProvider() {
        return new ObjectProvider<>() {
            @Override
            public T getObject(Object... args) {
                throw new UnsupportedOperationException();
            }

            @Override
            public T getIfAvailable() {
                return null;
            }

            @Override
            public T getIfAvailable(Supplier<T> defaultSupplier) {
                return defaultSupplier.get();
            }

            @Override
            public T getIfUnique() {
                return null;
            }

            @Override
            public T getObject() {
                throw new UnsupportedOperationException();
            }
        };
    }

    private static <T> ObjectProvider<T> singletonObjectProvider(T instance) {
        return new ObjectProvider<>() {
            @Override
            public T getObject(Object... args) {
                return instance;
            }

            @Override
            public T getIfAvailable() {
                return instance;
            }

            @Override
            public T getIfAvailable(Supplier<T> defaultSupplier) {
                return instance;
            }

            @Override
            public T getIfUnique() {
                return instance;
            }

            @Override
            public T getObject() {
                return instance;
            }
        };
    }
}
