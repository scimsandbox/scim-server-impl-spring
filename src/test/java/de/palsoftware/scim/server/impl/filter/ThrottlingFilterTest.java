package de.palsoftware.scim.server.impl.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.metrics.ScimOperationMetricsFilter;
import de.palsoftware.scim.server.impl.metrics.ScimRequestMetricAttributes;
import de.palsoftware.scim.server.impl.repository.WorkspaceTokenRepository;
import de.palsoftware.scim.server.impl.security.BearerTokenAuthFilter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Duration;
import java.util.List;
import java.util.Locale;
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
    void availablePermit_PassesThroughAndNormalizesWaitTimeoutBounds() throws Exception {
        AtomicReference<String> observedKey = new AtomicReference<>();
        AtomicReference<Duration> observedTimeout = new AtomicReference<>();
        ThrottlingFilter filter = new ThrottlingFilter((key, timeout) -> {
            observedKey.set(key);
            observedTimeout.set(timeout);
            return true;
        }, null, objectMapper);

        UUID wsId = UUID.randomUUID();
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/ws/" + wsId + "/scim/v2/Users");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(wsId.toString(), observedKey.get());
        assertEquals(Duration.ZERO, observedTimeout.get());
        assertEquals(ScimRequestMetricAttributes.THROTTLED_NO,
                request.getAttribute(ScimRequestMetricAttributes.THROTTLED));
        verify(filterChain).doFilter(request, response);

        // Negative waitTimeout normalizes to zero; > 5s caps at MAX_WAIT_TIMEOUT (5s)
        assertThat(ThrottlingFilter.resolveWaitTimeout(null)).isEqualTo(Duration.ZERO);
        assertThat(ThrottlingFilter.resolveWaitTimeout(Duration.ofMillis(-100))).isEqualTo(Duration.ZERO);
        assertThat(ThrottlingFilter.resolveWaitTimeout(Duration.ZERO)).isEqualTo(Duration.ZERO);
        assertThat(ThrottlingFilter.resolveWaitTimeout(Duration.ofMillis(250))).isEqualTo(Duration.ofMillis(250));
        assertThat(ThrottlingFilter.resolveWaitTimeout(Duration.ofSeconds(30)))
                .isEqualTo(ThrottlingFilter.MAX_WAIT_TIMEOUT);
    }

    @Test
    void exhaustedPermit_FailsFastWithScim429AndRetryAfterOneSecond() throws Exception {
        ThrottlingFilter filter = new ThrottlingFilter((_, _) -> false, Duration.ZERO, objectMapper);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/ws/123/scim/v2/Users");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(429, response.getStatus());
        assertEquals("1", response.getHeader("Retry-After"));
        assertEquals("application/scim+json;charset=UTF-8", response.getContentType());
        assertEquals(ScimRequestMetricAttributes.THROTTLED_YES,
                request.getAttribute(ScimRequestMetricAttributes.THROTTLED));

        String body = response.getContentAsString();
        assertTrue(body.contains("urn:ietf:params:scim:api:messages:2.0:Error"));
        assertTrue(body.contains("\"status\":\"429\""));
        assertTrue(body.contains("Too many requests. Try again later."));

        verifyNoInteractions(filterChain);
    }

    @Test
    void actuatorEndpoints_SkipThrottlingWithoutConsumingPermits() throws Exception {
        AtomicInteger permitsAcquired = new AtomicInteger();
        ThrottlingFilter filter = new ThrottlingFilter((_, _) -> {
            permitsAcquired.incrementAndGet();
            return false;
        }, Duration.ZERO, objectMapper);

        for (String actuatorPath : List.of("/actuator", "/actuator/health", "/actuator/health/liveness", "/actuator/prometheus")) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", actuatorPath);
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, filterChain);
            assertEquals(200, response.getStatus());
        }

        assertEquals(0, permitsAcquired.get());
        verify(filterChain, times(4)).doFilter(Mockito.any(), Mockito.any());
    }

    @Test
    void perWorkspaceIsolation_WorkspaceAExhaustedGets429WhileWorkspaceBSucceeds() throws Exception {
        AtomicLong fakeNanos = new AtomicLong(1_000_000_000L);
        ThrottlingFilter.KeyedPermitLimiter limiter =
                ThrottlingFilter.createPerWorkspaceLimiter(10.0, 3, fakeNanos::get);
        ThrottlingFilter filter = new ThrottlingFilter(limiter, Duration.ZERO, objectMapper);

        UUID workspaceA = UUID.randomUUID();
        UUID workspaceB = UUID.randomUUID();

        // Cold bucket for Workspace A allows all 3 burst requests immediately at t = 0 without spurious 429s
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest reqA = new MockHttpServletRequest("GET", "/ws/" + workspaceA + "/scim/v2/Users");
            MockHttpServletResponse respA = new MockHttpServletResponse();
            filter.doFilter(reqA, respA, filterChain);
            assertThat(respA.getStatus()).isEqualTo(200);
        }

        // 4th immediate request on Workspace A (uppercase UUID also maps to same canonical lowercase bucket) -> 429
        MockHttpServletRequest exhaustedReqA = new MockHttpServletRequest(
                "GET", "/ws/" + workspaceA.toString().toUpperCase(Locale.ROOT) + "/scim/v2/Users");
        MockHttpServletResponse exhaustedRespA = new MockHttpServletResponse();
        filter.doFilter(exhaustedReqA, exhaustedRespA, filterChain);
        assertThat(exhaustedRespA.getStatus()).isEqualTo(429);
        assertThat(exhaustedRespA.getHeader("Retry-After")).isEqualTo("1");

        // Concurrent requests on Workspace B succeed with 200 OK using Workspace B's independent bucket
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest reqB = new MockHttpServletRequest("GET", "/ws/" + workspaceB + "/scim/v2/Users");
            MockHttpServletResponse respB = new MockHttpServletResponse();
            filter.doFilter(reqB, respB, filterChain);
            assertThat(respB.getStatus()).isEqualTo(200);
        }

        // Advancing clock by 100ms at 10 rps replenishes 1 token for Workspace A
        fakeNanos.addAndGet(Duration.ofMillis(100).toNanos());
        MockHttpServletRequest refilledReqA = new MockHttpServletRequest("GET", "/ws/" + workspaceA + "/scim/v2/Users");
        MockHttpServletResponse refilledRespA = new MockHttpServletResponse();
        filter.doFilter(refilledReqA, refilledRespA, filterChain);
        assertThat(refilledRespA.getStatus()).isEqualTo(200);

        // Advancing clock by 10 seconds caps stored tokens at burst (3), not 100
        fakeNanos.addAndGet(Duration.ofSeconds(10).toNanos());
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest reqA = new MockHttpServletRequest("GET", "/ws/" + workspaceA + "/scim/v2/Users");
            MockHttpServletResponse respA = new MockHttpServletResponse();
            filter.doFilter(reqA, respA, filterChain);
            assertThat(respA.getStatus()).isEqualTo(200);
        }
        MockHttpServletRequest overCapReqA = new MockHttpServletRequest("GET", "/ws/" + workspaceA + "/scim/v2/Users");
        MockHttpServletResponse overCapRespA = new MockHttpServletResponse();
        filter.doFilter(overCapReqA, overCapRespA, filterChain);
        assertThat(overCapRespA.getStatus()).isEqualTo(429);
    }

    @Test
    void nonWorkspaceAndMalformedPaths_ShareSingleFallbackKeyWithoutAffectingWorkspaces() throws Exception {
        AtomicLong fakeNanos = new AtomicLong(0L);
        ThrottlingFilter.KeyedPermitLimiter limiter =
                ThrottlingFilter.createPerWorkspaceLimiter(5.0, 2, fakeNanos::get);
        ThrottlingFilter filter = new ThrottlingFilter(limiter, Duration.ZERO, objectMapper);

        assertThat(ThrottlingFilter.resolveRateLimitKey(null)).isEqualTo(ThrottlingFilter.NON_WORKSPACE_KEY);

        // Two distinct non-UUID paths consume the 2 tokens of the shared "__non_workspace__" bucket
        MockHttpServletRequest bad1 = new MockHttpServletRequest("GET", "/ws/not-uuid-1/scim/v2/Users");
        MockHttpServletResponse resp1 = new MockHttpServletResponse();
        filter.doFilter(bad1, resp1, filterChain);
        assertThat(resp1.getStatus()).isEqualTo(200);

        MockHttpServletRequest bad2 = new MockHttpServletRequest("GET", "/unmapped/path");
        MockHttpServletResponse resp2 = new MockHttpServletResponse();
        filter.doFilter(bad2, resp2, filterChain);
        assertThat(resp2.getStatus()).isEqualTo(200);

        // Third distinct malformed path hits 429 because all share "__non_workspace__"
        MockHttpServletRequest bad3 = new MockHttpServletRequest("GET", "/ws/not-uuid-3/scim/v2/Users");
        MockHttpServletResponse resp3 = new MockHttpServletResponse();
        filter.doFilter(bad3, resp3, filterChain);
        assertThat(resp3.getStatus()).isEqualTo(429);

        // Real workspace still has its full burst intact
        MockHttpServletRequest validWsReq = new MockHttpServletRequest(
                "GET", "/ws/" + UUID.randomUUID() + "/scim/v2/Users");
        MockHttpServletResponse validWsResp = new MockHttpServletResponse();
        filter.doFilter(validWsReq, validWsResp, filterChain);
        assertThat(validWsResp.getStatus()).isEqualTo(200);
    }

    @Test
    void waitTimeoutPositive_WaitsWhenWithinBudgetFailsFastWhenExceedingAndHandlesInterruption() throws Exception {
        AtomicLong fakeNanos = new AtomicLong(0L);
        AtomicLong totalSleptNanos = new AtomicLong(0L);
        // Deterministic sleeper that advances fakeNanos
        ThrottlingFilter.KeyedPermitLimiter limiter = ThrottlingFilter.createPerWorkspaceLimiter(
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
        ThrottlingFilter.KeyedPermitLimiter interruptibleLimiter = ThrottlingFilter.createPerWorkspaceLimiter(
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
        String wsPath = "/ws/" + UUID.randomUUID() + "/scim/v2/Users";

        // Drain initial token
        interruptFilter.doFilter(new MockHttpServletRequest("GET", wsPath), new MockHttpServletResponse(), filterChain);

        try {
            MockHttpServletResponse interruptedResp = new MockHttpServletResponse();
            interruptFilter.doFilter(new MockHttpServletRequest("GET", wsPath), interruptedResp, filterChain);
            assertThat(interruptedResp.getStatus()).isEqualTo(429);
            assertThat(Thread.currentThread().isInterrupted()).isTrue();
        } finally {
            Thread.interrupted(); // clear interrupt flag on test thread
        }

        // Because the interrupted reservation was refunded, the next caller only waits 100ms (not 200ms)
        shouldInterrupt.set(false);
        MockHttpServletResponse recoveredResp = new MockHttpServletResponse();
        ThrottlingFilter postInterruptFilter = new ThrottlingFilter(
                interruptibleLimiter, Duration.ofMillis(100), objectMapper);
        postInterruptFilter.doFilter(new MockHttpServletRequest("GET", wsPath), recoveredResp, filterChain);
        assertThat(recoveredResp.getStatus()).isEqualTo(200);
    }

    @Test
    void burstResolutionAndAutowiredConstructor_HandleDefaultsOverridesAndInvalidRates() throws Exception {
        assertThat(ThrottlingFilter.resolveBurst(0.5, 0)).isEqualTo(1);
        assertThat(ThrottlingFilter.resolveBurst(200.0, 0)).isEqualTo(200);
        assertThat(ThrottlingFilter.resolveBurst(200.4, -5)).isEqualTo(201);
        assertThat(ThrottlingFilter.resolveBurst(5000.0, 0)).isEqualTo(ThrottlingFilter.MAX_DEFAULT_BURST);
        assertThat(ThrottlingFilter.resolveBurst(200.0, 25)).isEqualTo(25);

        assertThatThrownBy(() -> ThrottlingFilter.createPerWorkspaceLimiter(0.0, 10))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ThrottlingFilter.createPerWorkspaceLimiter(-1.0, 10))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ThrottlingFilter.createPerWorkspaceLimiter(Double.NaN, 10))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ThrottlingFilter.createPerWorkspaceLimiter(Double.POSITIVE_INFINITY, 10))
                .isInstanceOf(IllegalArgumentException.class);

        // @Autowired constructor with empty ObjectProvider creates default per-workspace limiter
        ObjectProvider<ThrottlingFilter.KeyedPermitLimiter> emptyProvider = emptyObjectProvider();
        ThrottlingFilter defaultSpringFilter = new ThrottlingFilter(50.0, 0, Duration.ZERO, emptyProvider, objectMapper);
        MockHttpServletResponse okResp = new MockHttpServletResponse();
        defaultSpringFilter.doFilter(
                new MockHttpServletRequest("GET", "/ws/" + UUID.randomUUID() + "/scim/v2/Users"),
                okResp,
                filterChain);
        assertThat(okResp.getStatus()).isEqualTo(200);

        // @Autowired constructor with custom ObjectProvider uses injected KeyedPermitLimiter
        AtomicInteger customCalls = new AtomicInteger();
        ObjectProvider<ThrottlingFilter.KeyedPermitLimiter> customProvider = singletonObjectProvider((_, _) -> {
            customCalls.incrementAndGet();
            return true;
        });
        ThrottlingFilter customSpringFilter = new ThrottlingFilter(50.0, 0, Duration.ZERO, customProvider, objectMapper);
        customSpringFilter.doFilter(
                new MockHttpServletRequest("GET", "/ws/" + UUID.randomUUID() + "/scim/v2/Users"),
                new MockHttpServletResponse(),
                filterChain);
        assertThat(customCalls.get()).isEqualTo(1);
    }

    @Test
    void preAuthFilterOrdering_InvalidTokenFloodIsThrottledBeforeTokenRepositoryLookup() throws Exception {
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        ScimOperationMetricsFilter metricsFilter = new ScimOperationMetricsFilter(meterRegistry);
        AtomicLong fakeNanos = new AtomicLong(0L);
        ThrottlingFilter throttlingFilter = new ThrottlingFilter(
                ThrottlingFilter.createPerWorkspaceLimiter(1.0, 2, fakeNanos::get),
                Duration.ZERO,
                objectMapper);
        WorkspaceTokenRepository tokenRepository = Mockito.mock(WorkspaceTokenRepository.class);
        when(tokenRepository.findByTokenHashAndNotRevoked(anyString())).thenReturn(Optional.empty());
        BearerTokenAuthFilter bearerFilter = new BearerTokenAuthFilter(tokenRepository, objectMapper);

        UUID wsId = UUID.randomUUID();
        FilterChain pipeline = (req, res) -> throttlingFilter.doFilter(
                req, res, (r2, s2) -> bearerFilter.doFilter(r2, s2, filterChain));

        // First 2 invalid-token requests pass ThrottlingFilter and fail in BearerTokenAuthFilter (401)
        for (int i = 0; i < 2; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest("GET", "/ws/" + wsId + "/scim/v2/Users");
            req.addHeader("Authorization", "Bearer invalid-token-" + i);
            MockHttpServletResponse resp = new MockHttpServletResponse();
            metricsFilter.doFilter(req, resp, pipeline);
            assertThat(resp.getStatus()).isEqualTo(401);
        }

        // Next 4 invalid-token requests are rejected by ThrottlingFilter with 429 BEFORE BearerTokenAuthFilter
        for (int i = 0; i < 4; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest("GET", "/ws/" + wsId + "/scim/v2/Users");
            req.addHeader("Authorization", "Bearer invalid-flood-" + i);
            MockHttpServletResponse resp = new MockHttpServletResponse();
            metricsFilter.doFilter(req, resp, pipeline);
            assertThat(resp.getStatus()).isEqualTo(429);
            assertThat(resp.getHeader("Retry-After")).isEqualTo("1");
        }

        // Token repository was ONLY queried for the initial 2 burst requests, never during the 4 throttled requests
        verify(tokenRepository, times(2)).findByTokenHashAndNotRevoked(anyString());
        assertThat(meterRegistry.counter("scim.operation.throttled", "state", "no").count()).isEqualTo(2.0);
        assertThat(meterRegistry.counter("scim.operation.throttled", "state", "yes").count()).isEqualTo(4.0);
        assertThat(meterRegistry.counter("scim.operation.authentication", "state", "failed").count()).isEqualTo(2.0);
        assertThat(meterRegistry.counter("scim.operation.authentication", "state", "unknown").count()).isEqualTo(4.0);
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
