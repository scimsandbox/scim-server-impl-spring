package de.palsoftware.scim.server.impl.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.metrics.ScimOperationMetricsFilter;
import de.palsoftware.scim.server.impl.metrics.ScimRequestMetricAttributes;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.model.WorkspaceToken;
import de.palsoftware.scim.server.impl.repository.WorkspaceTokenRepository;
import de.palsoftware.scim.server.impl.security.BearerTokenAuthFilter;
import de.palsoftware.scim.server.impl.security.TokenSecurityUtil;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
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

        // Post-auth Global: 100 RPS burst ONLY 3; Pre-auth Per-IP: 10 RPS burst 2; Post-auth Per-Workspace: 10 RPS burst 3
        ThrottlingFilter preAuthFilter = new ThrottlingFilter(
                ThrottlingFilter.createPreAuthLimiter(100.0, 3, 10.0, 2, fakeNanos::get),
                Duration.ZERO,
                objectMapper);
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

        WorkspaceTokenRepository tokenRepository = Mockito.mock(WorkspaceTokenRepository.class);
        when(tokenRepository.findByTokenHashAndNotRevoked(anyString())).thenAnswer(inv -> {
            String hash = inv.getArgument(0);
            return validHashA.equals(hash) ? Optional.of(tokenEntityA) : Optional.empty();
        });
        BearerTokenAuthFilter bearerFilter = new BearerTokenAuthFilter(tokenRepository, objectMapper);

        FilterChain fullChain = (req, res) -> preAuthFilter.doFilter(
                req, res, (r2, s2) -> bearerFilter.doFilter(
                        r2, s2, (r3, s3) -> postAuthWsFilter.doFilter(r3, s3, filterChain)));

        // 1. Attacker IP 203.0.113.66 floods Workspace A with invalid tokens:
        //    First 2 hit 401; next 5 hit 429 in pre-auth ThrottlingFilter with 0 DB queries!
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

        // 3. Distributed unauthenticated 401 flood across 50 distinct IPs & IPv6 /64 prefixes
        //    (plus anonymous discovery requests) when post-auth global burst is ONLY 3:
        //    consumes 0 global tokens and 0 workspace tokens!
        for (int idx = 1; idx <= 25; idx++) {
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
        for (int idx = 1; idx <= 10; idx++) {
            MockHttpServletRequest anonDiscovery = new MockHttpServletRequest(
                    "GET", "/ws/" + workspaceA + "/scim/v2/ServiceProviderConfig");
            anonDiscovery.setRemoteAddr("198.18.0." + idx);
            MockHttpServletResponse anonResp = new MockHttpServletResponse();
            metricsFilter.doFilter(anonDiscovery, anonResp, fullChain);
            assertThat(anonResp.getStatus()).isEqualTo(200);
        }

        // 4. Legitimate Workspace A client STILL has ALL 3 post-auth global + workspace permits!
        for (String legitIp : List.of("198.51.100.10", "198.51.100.10", "198.51.100.11")) {
            MockHttpServletRequest legitReq = new MockHttpServletRequest("GET", "/ws/" + workspaceA + "/scim/v2/Users");
            legitReq.setRemoteAddr(legitIp);
            legitReq.addHeader("Authorization", "Bearer " + rawValidTokenA);
            MockHttpServletResponse legitResp = new MockHttpServletResponse();
            metricsFilter.doFilter(legitReq, legitResp, fullChain);
            assertThat(legitResp.getStatus()).isEqualTo(200);
        }

        // 5. 4th authenticated request on Workspace A (even from fresh IP 198.51.100.11) hits post-auth cap (429)!
        MockHttpServletRequest overWsCap = new MockHttpServletRequest("GET", "/ws/" + workspaceA + "/scim/v2/Users");
        overWsCap.setRemoteAddr("198.51.100.11");
        overWsCap.addHeader("Authorization", "Bearer " + rawValidTokenA);
        MockHttpServletResponse overWsResp = new MockHttpServletResponse();
        metricsFilter.doFilter(overWsCap, overWsResp, fullChain);
        assertThat(overWsResp.getStatus()).isEqualTo(429);
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
    void trustedProxyClientIpExtraction_GatesCfConnectingIpWalksXffRightToLeftAndMasksIpv6To64() throws Exception {
        assertThat(ThrottlingFilter.extractClientIpKey(null, List.of()))
                .isEqualTo(ThrottlingFilter.GLOBAL_FALLBACK_KEY);

        MockHttpServletRequest blankRemote = new MockHttpServletRequest();
        blankRemote.setRemoteAddr("   ");
        assertThat(ThrottlingFilter.extractClientIpKey(blankRemote, List.of()))
                .isEqualTo(ThrottlingFilter.GLOBAL_FALLBACK_KEY);

        // 1. Public peer MUST ignore spoofed CF-Connecting-IP and X-Forwarded-For when trustedProxies is empty
        MockHttpServletRequest publicPeer = new MockHttpServletRequest();
        publicPeer.setRemoteAddr("198.51.100.99:54321");
        publicPeer.addHeader("CF-Connecting-IP", "203.0.113.1");
        publicPeer.addHeader("X-Forwarded-For", "203.0.113.2");
        assertThat(ThrottlingFilter.extractClientIpKey(publicPeer, List.of()))
                .isEqualTo("ip:198.51.100.99");

        // Public IPv6 peer ignores forwarded headers and keys by /64 prefix
        MockHttpServletRequest publicV6Peer = new MockHttpServletRequest();
        publicV6Peer.setRemoteAddr("[2001:db8:1111:2222:aaaa:bbbb:cccc:5]:8443");
        publicV6Peer.addHeader("X-Forwarded-For", "203.0.113.2");
        assertThat(ThrottlingFilter.extractClientIpKey(publicV6Peer, List.of()))
                .isEqualTo("ip:2001:db8:1111:2222:0:0:0:0/64");

        // IPv4-mapped IPv6 literal unmaps to /32 IPv4 key (never /64 IPv6!)
        MockHttpServletRequest mappedV4Peer = new MockHttpServletRequest();
        mappedV4Peer.setRemoteAddr("::ffff:192.0.2.5");
        assertThat(ThrottlingFilter.extractClientIpKey(mappedV4Peer, List.of()))
                .isEqualTo("ip:192.0.2.5");

        // 2. Default empty trustedProxies trusts loopback, RFC1918, IPv6 ULA (fc00::/7), and link-local for XFF
        for (String trustedPeer : List.of("127.0.0.1", "::1", "10.1.2.3", "172.16.5.4", "192.168.1.1",
                "fd12:3456:789a::1", "fc00::1", "169.254.10.20", "fe80::1%en0")) {
            MockHttpServletRequest proxyReq = new MockHttpServletRequest();
            proxyReq.setRemoteAddr(trustedPeer);
            proxyReq.addHeader("X-Forwarded-For", "198.51.100.50, 203.0.113.77");
            assertThat(ThrottlingFilter.extractClientIpKey(proxyReq, List.of()))
                    .as("Peer %s should resolve rightmost untrusted XFF hop", trustedPeer)
                    .isEqualTo("ip:203.0.113.77");
        }

        // 3. CF-Connecting-IP MUST be ignored when trusted-cloudflare-proxies is empty (prevents Nginx/ALB bypass!)
        MockHttpServletRequest spoofedCfBehindAlb = new MockHttpServletRequest();
        spoofedCfBehindAlb.setRemoteAddr("10.0.0.2");
        spoofedCfBehindAlb.addHeader("CF-Connecting-IP", "203.0.113.88");
        spoofedCfBehindAlb.addHeader("X-Forwarded-For", "198.51.100.1");
        assertThat(ThrottlingFilter.extractClientIpKey(spoofedCfBehindAlb, List.of(), List.of()))
                .isEqualTo("ip:198.51.100.1");

        // When peer matches trusted-cloudflare-proxies, valid single CF-Connecting-IP is used;
        // duplicate or comma-separated CF-Connecting-IP falls back to X-Forwarded-For
        List<IpAddressMatcher> cfProxies = ThrottlingFilter.parseTrustedProxies("173.245.48.0/20, 2400:cb00::/32");
        MockHttpServletRequest validCfReq = new MockHttpServletRequest();
        validCfReq.setRemoteAddr("173.245.48.12");
        validCfReq.addHeader("CF-Connecting-IP", "203.0.113.88");
        validCfReq.addHeader("X-Forwarded-For", "198.51.100.1");
        assertThat(ThrottlingFilter.extractClientIpKey(validCfReq, List.of(), cfProxies))
                .isEqualTo("ip:203.0.113.88");

        MockHttpServletRequest multiCfReq = new MockHttpServletRequest();
        multiCfReq.setRemoteAddr("173.245.48.12");
        multiCfReq.addHeader("CF-Connecting-IP", "203.0.113.1");
        multiCfReq.addHeader("CF-Connecting-IP", "203.0.113.2");
        multiCfReq.addHeader("X-Forwarded-For", "198.51.100.44");
        assertThat(ThrottlingFilter.extractClientIpKey(multiCfReq, List.of(), cfProxies))
                .isEqualTo("ip:198.51.100.44");

        MockHttpServletRequest commaCfReq = new MockHttpServletRequest();
        commaCfReq.setRemoteAddr("173.245.48.12");
        commaCfReq.addHeader("CF-Connecting-IP", "203.0.113.1, 203.0.113.2");
        commaCfReq.addHeader("X-Forwarded-For", "198.51.100.45");
        assertThat(ThrottlingFilter.extractClientIpKey(commaCfReq, List.of(), cfProxies))
                .isEqualTo("ip:198.51.100.45");

        MockHttpServletRequest noCfHeaderReq = new MockHttpServletRequest();
        noCfHeaderReq.setRemoteAddr("[2400:cb00::1]");
        noCfHeaderReq.addHeader("X-Forwarded-For", "198.51.100.46");
        assertThat(ThrottlingFilter.extractClientIpKey(noCfHeaderReq, List.of(), cfProxies))
                .isEqualTo("ip:198.51.100.46");

        // 4. Right-to-left multi-hop X-Forwarded-For walking across multi-tier proxies, trailing blanks, and spoofed hops
        MockHttpServletRequest twoTierProxy = new MockHttpServletRequest();
        twoTierProxy.setRemoteAddr("10.0.2.4"); // K8s Ingress
        twoTierProxy.addHeader("X-Forwarded-For", "spoofed.by.client, 198.51.100.55");
        twoTierProxy.addHeader("X-Forwarded-For", "10.0.1.9,   "); // ALB + trailing blank
        twoTierProxy.addHeader("X-Forwarded-For", "   "); // trailing blank header
        assertThat(ThrottlingFilter.extractClientIpKey(twoTierProxy, List.of(), List.of()))
                .isEqualTo("ip:198.51.100.55");

        // Malformed hop stops walking immediately and returns lastTrustedHop (never trusting entries further left!)
        MockHttpServletRequest malformedMiddleHop = new MockHttpServletRequest();
        malformedMiddleHop.setRemoteAddr("10.0.2.4");
        malformedMiddleHop.addHeader("X-Forwarded-For", "203.0.113.1, bogus-hop, 10.0.1.9");
        assertThat(ThrottlingFilter.extractClientIpKey(malformedMiddleHop, List.of(), List.of()))
                .isEqualTo("ip:10.0.1.9");

        // Malformed rightmost hop with no trusted hop yet falls back to peerAddr
        MockHttpServletRequest malformedRightmostHop = new MockHttpServletRequest();
        malformedRightmostHop.setRemoteAddr("10.0.2.4");
        malformedRightmostHop.addHeader("X-Forwarded-For", "203.0.113.1, bogus-hop");
        assertThat(ThrottlingFilter.extractClientIpKey(malformedRightmostHop, List.of(), List.of()))
                .isEqualTo("ip:10.0.2.4");

        // All-trusted XFF chain returns leftmost trusted hop
        MockHttpServletRequest allTrustedHops = new MockHttpServletRequest();
        allTrustedHops.setRemoteAddr("10.0.2.4");
        allTrustedHops.addHeader("X-Forwarded-For", "10.0.1.1, 10.0.1.2");
        assertThat(ThrottlingFilter.extractClientIpKey(allTrustedHops, List.of(), List.of()))
                .isEqualTo("ip:10.0.1.1");

        // 5. Explicit trusted-proxies CIDR list (including non-byte-aligned /12, /25, /57 CIDRs)
        List<IpAddressMatcher> explicitProxies = ThrottlingFilter.parseTrustedProxies(
                "172.16.0.0/12, 198.51.100.128/25, 2001:db8:abcd:ef80::/57, ::ffff:192.0.2.0/120, 203.0.113.250");
        MockHttpServletRequest untrustedPrivate = new MockHttpServletRequest();
        untrustedPrivate.setRemoteAddr("10.0.0.2");
        untrustedPrivate.addHeader("X-Forwarded-For", "203.0.113.9");
        assertThat(ThrottlingFilter.extractClientIpKey(untrustedPrivate, explicitProxies))
                .isEqualTo("ip:10.0.0.2");

        // Non-byte-aligned /12: 172.31.255.254 matches, 172.32.0.1 does not
        MockHttpServletRequest matchingSlash12 = new MockHttpServletRequest();
        matchingSlash12.setRemoteAddr("172.31.255.254");
        matchingSlash12.addHeader("X-Forwarded-For", "203.0.113.9");
        assertThat(ThrottlingFilter.extractClientIpKey(matchingSlash12, explicitProxies))
                .isEqualTo("ip:203.0.113.9");

        MockHttpServletRequest outsideSlash12 = new MockHttpServletRequest();
        outsideSlash12.setRemoteAddr("172.32.0.1");
        outsideSlash12.addHeader("X-Forwarded-For", "203.0.113.9");
        assertThat(ThrottlingFilter.extractClientIpKey(outsideSlash12, explicitProxies))
                .isEqualTo("ip:172.32.0.1");

        // Non-byte-aligned /25: .129 matches, .127 and 198.51.101.129 do not
        MockHttpServletRequest matchingSlash25 = new MockHttpServletRequest();
        matchingSlash25.setRemoteAddr("198.51.100.129");
        matchingSlash25.addHeader("X-Forwarded-For", "203.0.113.10");
        assertThat(ThrottlingFilter.extractClientIpKey(matchingSlash25, explicitProxies))
                .isEqualTo("ip:203.0.113.10");

        MockHttpServletRequest outsideSlash25Low = new MockHttpServletRequest();
        outsideSlash25Low.setRemoteAddr("198.51.100.127");
        outsideSlash25Low.addHeader("X-Forwarded-For", "203.0.113.10");
        assertThat(ThrottlingFilter.extractClientIpKey(outsideSlash25Low, explicitProxies))
                .isEqualTo("ip:198.51.100.127");

        // Non-byte-aligned IPv6 /57 + Cloudflare IPv6 /64 client key
        MockHttpServletRequest matchingSlash57V6 = new MockHttpServletRequest();
        matchingSlash57V6.setRemoteAddr("2001:db8:abcd:efff::9");
        matchingSlash57V6.addHeader("X-Forwarded-For", "2001:0db8:0001:0002:aaaa:bbbb:cccc:0001");
        assertThat(ThrottlingFilter.extractClientIpKey(matchingSlash57V6, explicitProxies))
                .isEqualTo("ip:2001:db8:1:2:0:0:0:0/64");
        assertThat(ClientIpResolver.matchesAny(null, explicitProxies)).isFalse();
        assertThat(ClientIpResolver.matchesAny(ThrottlingFilter.parseIpLiteral("10.0.0.1"), null)).isFalse();
        assertThat(ClientIpResolver.matchesAny(ThrottlingFilter.parseIpLiteral("10.0.0.1"), List.of())).isFalse();
        assertThat(ClientIpResolver.isTrustedProxyPeer(null, explicitProxies)).isFalse();
        assertThat(ClientIpResolver.splitHostFromRemoteAddr("")).isEmpty();

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

        // 6. IPv6 /64 bucketing prevents interface-ID rotation bypass while isolating distinct /64 prefixes
        AtomicLong v6Clock = new AtomicLong(0L);
        ThrottlingFilter ipv6Filter = new ThrottlingFilter(
                ThrottlingFilter.createPreAuthLimiter(100.0, 20, 10.0, 1, v6Clock::get),
                Duration.ZERO,
                objectMapper);
        String scimPath = "/ws/" + UUID.randomUUID() + "/scim/v2/Users";

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

        // 7. Non-numeric hostnames, malformed zone IDs, and ambiguous IPv4 forms never trigger DNS lookups
        MockHttpServletRequest hostnamePeer = new MockHttpServletRequest();
        hostnamePeer.setRemoteAddr("nonexistent-host.invalid");
        assertThat(ThrottlingFilter.extractClientIpKey(hostnamePeer, List.of()))
                .isEqualTo("ip:nonexistent-host.invalid");
        assertThat(ThrottlingFilter.parseIpLiteral(null)).isNull();
        assertThat(ThrottlingFilter.parseIpLiteral("   ")).isNull();
        assertThat(ThrottlingFilter.parseIpLiteral("010.0.0.1")).isNull();
        assertThat(ThrottlingFilter.parseIpLiteral("127.1")).isNull();
        assertThat(ThrottlingFilter.parseIpLiteral("192.168.1.abc")).isNull();
        assertThat(ThrottlingFilter.parseIpLiteral("256.0.0.1")).isNull();
        assertThat(ThrottlingFilter.parseIpLiteral("2001:db8:::1")).isNull();
        assertThat(ThrottlingFilter.parseIpLiteral("[2001:db8::1]")).isNotNull();
        assertThat(ThrottlingFilter.parseIpLiteral("%en0")).isNull();
        assertThat(ThrottlingFilter.parseIpLiteral("127.0.0.1%:1")).isNull();
        assertThat(ThrottlingFilter.parseIpLiteral("fe80::1%")).isNull();
        assertThat(ThrottlingFilter.parseIpLiteral("[127.0.0.1]")).isNull();

        assertThat(ClientIpResolver.splitHostFromRemoteAddr("[2001:db8::1]")).isEqualTo("2001:db8::1");
        assertThat(ClientIpResolver.splitHostFromRemoteAddr("[]")).isEqualTo("[]");
        assertThat(ClientIpResolver.splitHostFromRemoteAddr("[2001:db8::1]:")).isEqualTo("[2001:db8::1]:");
        assertThat(ClientIpResolver.splitHostFromRemoteAddr("[2001:db8::1]:abc")).isEqualTo("[2001:db8::1]:abc");
        assertThat(ClientIpResolver.splitHostFromRemoteAddr("[2001:db8::1]:70000")).isEqualTo("[2001:db8::1]:70000");
        assertThat(ClientIpResolver.splitHostFromRemoteAddr("198.51.100.1:0")).isEqualTo("198.51.100.1:0");
        assertThat(ThrottlingFilter.parseTrustedProxies("10.0.0.0/8, , ")).hasSize(1);

        assertThatThrownBy(() -> ThrottlingFilter.parseTrustedProxies("not-an-ip"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ThrottlingFilter.parseTrustedProxies("not-an-ip/24"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ThrottlingFilter.parseTrustedProxies("10.0.0.0/-1"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ThrottlingFilter.parseTrustedProxies("10.0.0.0/33"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ThrottlingFilter.parseTrustedProxies("10.0.0.0/abc"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ThrottlingFilter.parseTrustedProxies("10.0.0.0/8/16"))
                .isInstanceOf(IllegalArgumentException.class);
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
    void subRateLimitDefaultsOverridesAndAutowiredConstructors_BehaveAccurately() throws Exception {
        assertThat(ThrottlingFilter.resolveBurst(0.5, 0)).isEqualTo(1);
        assertThat(ThrottlingFilter.resolveBurst(200.0, 0)).isEqualTo(200);
        assertThat(ThrottlingFilter.resolveBurst(200.4, -5)).isEqualTo(201);
        assertThat(ThrottlingFilter.resolveBurst(5000.0, 0)).isEqualTo(ThrottlingFilter.MAX_DEFAULT_BURST);
        assertThat(ThrottlingFilter.resolveBurst(200.0, 25)).isEqualTo(25);

        // Sub-rate-limit defaults: min(globalRPS, 250.0) and min(resolvedGlobalBurst, 250)
        assertThat(ThrottlingFilter.resolveSubRateLimit(100.0, 0, 0.0, 0))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(100.0, 100));
        assertThat(ThrottlingFilter.resolveSubRateLimit(800.0, 0, 0.0, 0))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(250.0, 250));
        assertThat(ThrottlingFilter.resolveSubRateLimit(0.2, 10, 0.0, 0))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(0.2, 10));
        // Explicit subRPS > 0 with subBurst = 0 uses resolveBurst(subRPS, 0)
        assertThat(ThrottlingFilter.resolveSubRateLimit(200.0, 200, 15.2, 0))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(15.2, 16));
        // Explicit subBurst > 0 overrides
        assertThat(ThrottlingFilter.resolveSubRateLimit(200.0, 200, 0.0, 42))
                .isEqualTo(new ThrottlingFilter.SubRateLimit(200.0, 42));

        assertThatThrownBy(() -> ThrottlingFilter.createPreAuthLimiter(0.0, 10, 0.0, 0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ThrottlingFilter.createPreAuthLimiter(-1.0, 10, 0.0, 0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ThrottlingFilter.createPreAuthLimiter(Double.NaN, 10, 0.0, 0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ThrottlingFilter.createPreAuthLimiter(10.0, 10, Double.POSITIVE_INFINITY, 0))
                .isInstanceOf(IllegalArgumentException.class);

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
