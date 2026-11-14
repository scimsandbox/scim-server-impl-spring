package de.palsoftware.scim.server.impl.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import de.palsoftware.scim.server.impl.metrics.ScimRequestMetricAttributes;
import de.palsoftware.scim.server.impl.security.RequestPaths;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

@Component
@ConditionalOnProperty(prefix = "app.rate-limit", name = "enabled", havingValue = "true", matchIfMissing = false)
public class ThrottlingFilter extends OncePerRequestFilter {

    static final Duration DEFAULT_WAIT_TIMEOUT = Duration.ZERO;
    static final Duration MAX_WAIT_TIMEOUT = Duration.ofSeconds(5);
    static final int MAX_DEFAULT_BURST = 1_000;
    static final long MAX_CACHED_WORKSPACES = 10_000L;
    static final Duration BUCKET_IDLE_EXPIRATION = Duration.ofMinutes(15);
    static final String NON_WORKSPACE_KEY = "__non_workspace__";
    static final String RETRY_AFTER_SECONDS = "1";
    static final String CAPACITY_ERROR_DETAIL = "Too many requests. Try again later.";

    private final KeyedPermitLimiter permitLimiter;
    private final Duration waitTimeout;
    private final ObjectMapper objectMapper;

    @Autowired
    public ThrottlingFilter(@Value("${app.rate-limit.requests-per-second}") double requestsPerSecond,
                            @Value("${app.rate-limit.burst:0}") int configuredBurst,
                            @Value("${app.rate-limit.wait-timeout:0s}") Duration waitTimeout,
                            ObjectProvider<KeyedPermitLimiter> permitLimiterProvider,
                            ObjectMapper objectMapper) {
        this(
                permitLimiterProvider.getIfAvailable(
                        () -> createPerWorkspaceLimiter(requestsPerSecond, configuredBurst, System::nanoTime)),
                waitTimeout,
                objectMapper
        );
    }

    public ThrottlingFilter(KeyedPermitLimiter permitLimiter,
                            Duration waitTimeout,
                            ObjectMapper objectMapper) {
        this.permitLimiter = Objects.requireNonNull(permitLimiter, "permitLimiter must not be null");
        this.waitTimeout = resolveWaitTimeout(waitTimeout);
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    }

    public static KeyedPermitLimiter createPerWorkspaceLimiter(double requestsPerSecond, int configuredBurst) {
        return createPerWorkspaceLimiter(requestsPerSecond, configuredBurst, System::nanoTime);
    }

    static KeyedPermitLimiter createPerWorkspaceLimiter(double requestsPerSecond,
                                                        int configuredBurst,
                                                        LongSupplier nanoClock) {
        return createPerWorkspaceLimiter(requestsPerSecond, configuredBurst, nanoClock, TimeUnit.NANOSECONDS::sleep);
    }

    static KeyedPermitLimiter createPerWorkspaceLimiter(double requestsPerSecond,
                                                        int configuredBurst,
                                                        LongSupplier nanoClock,
                                                        NanoSleeper sleeper) {
        if (!Double.isFinite(requestsPerSecond) || requestsPerSecond <= 0.0) {
            throw new IllegalArgumentException("requestsPerSecond must be a finite positive number");
        }
        Objects.requireNonNull(nanoClock, "nanoClock must not be null");
        Objects.requireNonNull(sleeper, "sleeper must not be null");

        int resolvedBurst = resolveBurst(requestsPerSecond, configuredBurst);
        LoadingCache<String, TokenBucket> buckets = Caffeine.newBuilder()
                .maximumSize(MAX_CACHED_WORKSPACES)
                .expireAfterAccess(BUCKET_IDLE_EXPIRATION)
                .build(key -> new TokenBucket(requestsPerSecond, resolvedBurst, nanoClock, sleeper));
        return (key, timeout) -> {
            TokenBucket bucket = Objects.requireNonNull(buckets.get(key != null ? key : NON_WORKSPACE_KEY));
            return bucket.tryAcquire(timeout);
        };
    }

    static int resolveBurst(double requestsPerSecond, int configuredBurst) {
        if (configuredBurst > 0) {
            return configuredBurst;
        }
        return Math.max(1, Math.min(MAX_DEFAULT_BURST, (int) Math.ceil(requestsPerSecond)));
    }

    static Duration resolveWaitTimeout(Duration configuredWaitTimeout) {
        if (configuredWaitTimeout == null || configuredWaitTimeout.isNegative() || configuredWaitTimeout.isZero()) {
            return DEFAULT_WAIT_TIMEOUT;
        }
        if (configuredWaitTimeout.compareTo(MAX_WAIT_TIMEOUT) > 0) {
            return MAX_WAIT_TIMEOUT;
        }
        return configuredWaitTimeout;
    }

    static String resolveRateLimitKey(HttpServletRequest request) {
        if (request == null) {
            return NON_WORKSPACE_KEY;
        }
        UUID workspaceId = RequestPaths.extractWorkspaceId(request.getRequestURI());
        return workspaceId != null ? workspaceId.toString() : NON_WORKSPACE_KEY;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return RequestPaths.isActuatorPath(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        request.setAttribute(ScimRequestMetricAttributes.THROTTLED, ScimRequestMetricAttributes.THROTTLED_NO);

        String rateLimitKey = resolveRateLimitKey(request);
        if (!permitLimiter.tryAcquire(rateLimitKey, waitTimeout)) {
            request.setAttribute(ScimRequestMetricAttributes.THROTTLED, ScimRequestMetricAttributes.THROTTLED_YES);
            sendScimRateLimitError(response);
            return;
        }

        chain.doFilter(request, response);
    }

    private void sendScimRateLimitError(HttpServletResponse response) throws IOException {
        int status = HttpStatus.TOO_MANY_REQUESTS.value();
        response.setStatus(status);
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Retry-After", RETRY_AFTER_SECONDS);
        response.setContentType("application/scim+json;charset=UTF-8");

        Map<String, Object> error = new LinkedHashMap<>();
        error.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:Error"));
        error.put("status", String.valueOf(status));
        error.put("detail", CAPACITY_ERROR_DETAIL);

        response.getWriter().write(objectMapper.writeValueAsString(error));
        response.getWriter().flush();
    }

    @FunctionalInterface
    public interface KeyedPermitLimiter {
        boolean tryAcquire(String key, Duration timeout);
    }

    @FunctionalInterface
    interface NanoSleeper {
        void sleepNanos(long nanos) throws InterruptedException;
    }

    static final class TokenBucket {
        private static final double NANOS_PER_SECOND = 1_000_000_000.0;

        private final double requestsPerSecond;
        private final double maxTokens;
        private final LongSupplier nanoClock;
        private final NanoSleeper sleeper;

        private double storedTokens;
        private long lastRefillNanos;

        TokenBucket(double requestsPerSecond, int burst, LongSupplier nanoClock, NanoSleeper sleeper) {
            this.requestsPerSecond = requestsPerSecond;
            this.maxTokens = burst;
            this.nanoClock = nanoClock;
            this.sleeper = sleeper;
            this.storedTokens = burst;
            this.lastRefillNanos = nanoClock.getAsLong();
        }

        boolean tryAcquire(Duration timeout) {
            if (timeout == null || timeout.isZero() || timeout.isNegative()) {
                return tryAcquireImmediate();
            }
            return tryAcquireWithTimeout(timeout.toNanos());
        }

        private synchronized boolean tryAcquireImmediate() {
            refill(nanoClock.getAsLong());
            if (storedTokens >= 1.0) {
                storedTokens -= 1.0;
                return true;
            }
            return false;
        }

        private boolean tryAcquireWithTimeout(long timeoutNanos) {
            long waitNanos;
            synchronized (this) {
                refill(nanoClock.getAsLong());
                if (storedTokens >= 1.0) {
                    storedTokens -= 1.0;
                    return true;
                }
                double deficit = 1.0 - storedTokens;
                double requiredNanos = (deficit * NANOS_PER_SECOND) / requestsPerSecond;
                if (requiredNanos > timeoutNanos) {
                    return false;
                }
                waitNanos = (long) Math.ceil(requiredNanos);
                storedTokens -= 1.0;
            }

            if (waitNanos <= 0L) {
                return true;
            }

            try {
                sleeper.sleepNanos(waitNanos);
                return true;
            } catch (InterruptedException _) {
                synchronized (this) {
                    refill(nanoClock.getAsLong());
                    storedTokens = Math.min(maxTokens, storedTokens + 1.0);
                }
                Thread.currentThread().interrupt();
                return false;
            }
        }

        private void refill(long nowNanos) {
            long elapsedNanos = nowNanos - lastRefillNanos;
            if (elapsedNanos > 0L) {
                double replenished = (elapsedNanos * requestsPerSecond) / NANOS_PER_SECOND;
                storedTokens = Math.min(maxTokens, storedTokens + replenished);
                lastRefillNanos = nowNanos;
            }
        }
    }
}
