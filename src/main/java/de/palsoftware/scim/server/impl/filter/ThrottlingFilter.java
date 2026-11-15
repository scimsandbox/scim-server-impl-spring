package de.palsoftware.scim.server.impl.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import de.palsoftware.scim.server.impl.metrics.ScimRequestMetricAttributes;
import de.palsoftware.scim.server.impl.scim.error.ScimFilterErrorWriter;
import de.palsoftware.scim.server.impl.security.RequestPaths;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/**
 * Tier 1 pre-authentication SCIM rate-limiting filter enforcing per-client-IP (and IPv6 {@code /64}
 * prefix) token buckets.
 * <p>
 * Protects {@code WorkspaceTokenRepository} against unauthenticated random-UUID or invalid-token
 * floods from any client IP without consuming permits from any workspace bucket or the pod-wide
 * global cap (which are enforced strictly post-authentication in {@link WorkspaceRateLimitFilter}).
 */
@Component
@ConditionalOnProperty(prefix = "app.rate-limit", name = "enabled", havingValue = "true", matchIfMissing = false)
public class ThrottlingFilter extends OncePerRequestFilter {

    static final Duration DEFAULT_WAIT_TIMEOUT = Duration.ZERO;
    static final Duration MAX_WAIT_TIMEOUT = Duration.ofSeconds(5);
    static final int MAX_DEFAULT_BURST = 1_000;
    static final double DEFAULT_SUB_DIVISOR = 4.0;
    static final long MAX_CACHED_KEYS = 10_000L;
    static final Duration BUCKET_IDLE_EXPIRATION = Duration.ofMinutes(15);
    static final long MAX_VERIFIED_TOKENS = 50_000L;
    static final Duration VERIFIED_TOKEN_IDLE_EXPIRATION = Duration.ofHours(24);
    static final String GLOBAL_FALLBACK_KEY = "global";
    public static final String CAPACITY_ERROR_DETAIL = "Too many requests. Try again later.";
    public static final String RESOLVED_CLIENT_IP_KEY_ATTRIBUTE =
            ThrottlingFilter.class.getName() + ".RESOLVED_CLIENT_IP_KEY";

    private static final String NANO_CLOCK_NULL_MSG = "nanoClock must not be null";
    private static final String SLEEPER_NULL_MSG = "sleeper must not be null";

    private final KeyedPermitLimiter permitLimiter;
    private final List<IpAddressMatcher> trustedProxies;
    private final List<IpAddressMatcher> trustedCloudflareProxies;
    private final Duration waitTimeout;
    private final ObjectMapper objectMapper;

    @Autowired
    public ThrottlingFilter(
            @Value("${app.rate-limit.requests-per-second}") double globalRequestsPerSecond,
            @Value("${app.rate-limit.burst:0}") int globalBurst,
            @Value("${app.rate-limit.per-ip-requests-per-second:0}") double perIpRequestsPerSecond,
            @Value("${app.rate-limit.per-ip-burst:0}") int perIpBurst,
            @Value("${app.rate-limit.trusted-proxies:}") String configuredTrustedProxies,
            @Value("${app.rate-limit.trusted-cloudflare-proxies:}") String configuredTrustedCloudflareProxies,
            @Value("${app.rate-limit.wait-timeout:0s}") Duration waitTimeout,
            ObjectProvider<KeyedPermitLimiter> permitLimiterProvider,
            ObjectMapper objectMapper) {
        this(
                permitLimiterProvider.getIfAvailable(() -> createPreAuthLimiter(
                        globalRequestsPerSecond, globalBurst, perIpRequestsPerSecond, perIpBurst)),
                ClientIpResolver.parseTrustedProxies(configuredTrustedProxies),
                ClientIpResolver.parseTrustedProxies(configuredTrustedCloudflareProxies),
                waitTimeout,
                objectMapper
        );
    }

    public ThrottlingFilter(KeyedPermitLimiter permitLimiter,
                            Duration waitTimeout,
                            ObjectMapper objectMapper) {
        this(permitLimiter, List.of(), List.of(), waitTimeout, objectMapper);
    }

    public ThrottlingFilter(KeyedPermitLimiter permitLimiter,
                            List<IpAddressMatcher> trustedProxies,
                            Duration waitTimeout,
                            ObjectMapper objectMapper) {
        this(permitLimiter, trustedProxies, List.of(), waitTimeout, objectMapper);
    }

    public ThrottlingFilter(KeyedPermitLimiter permitLimiter,
                            List<IpAddressMatcher> trustedProxies,
                            List<IpAddressMatcher> trustedCloudflareProxies,
                            Duration waitTimeout,
                            ObjectMapper objectMapper) {
        this.permitLimiter = Objects.requireNonNull(permitLimiter, "permitLimiter must not be null");
        this.trustedProxies = trustedProxies != null ? List.copyOf(trustedProxies) : List.of();
        this.trustedCloudflareProxies = trustedCloudflareProxies != null
                ? List.copyOf(trustedCloudflareProxies)
                : List.of();
        this.waitTimeout = resolveWaitTimeout(waitTimeout);
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    }

    public static KeyedPermitLimiter createPreAuthLimiter(double globalRequestsPerSecond,
                                                          int globalBurst,
                                                          double perIpRequestsPerSecond,
                                                          int perIpBurst) {
        return createPreAuthLimiter(
                globalRequestsPerSecond,
                globalBurst,
                perIpRequestsPerSecond,
                perIpBurst,
                System::nanoTime,
                TimeUnit.NANOSECONDS::sleep);
    }

    static KeyedPermitLimiter createPreAuthLimiter(double globalRequestsPerSecond,
                                                   int globalBurst,
                                                   double perIpRequestsPerSecond,
                                                   int perIpBurst,
                                                   LongSupplier nanoClock) {
        return createPreAuthLimiter(
                globalRequestsPerSecond,
                globalBurst,
                perIpRequestsPerSecond,
                perIpBurst,
                nanoClock,
                TimeUnit.NANOSECONDS::sleep);
    }

    static KeyedPermitLimiter createPreAuthLimiter(double globalRequestsPerSecond,
                                                   int globalBurst,
                                                   double perIpRequestsPerSecond,
                                                   int perIpBurst,
                                                   LongSupplier nanoClock,
                                                   NanoSleeper sleeper) {
        SubRateLimit ipLimit = resolveSubRateLimit(
                globalRequestsPerSecond, globalBurst, perIpRequestsPerSecond, perIpBurst);
        return createKeyedLimiter(ipLimit.requestsPerSecond(), ipLimit.burst(), nanoClock, sleeper);
    }

    public static KeyedPermitLimiter createPostAuthLimiter(double globalRequestsPerSecond,
                                                           int globalBurst,
                                                           double perWorkspaceRequestsPerSecond,
                                                           int perWorkspaceBurst) {
        return createPostAuthLimiter(
                globalRequestsPerSecond,
                globalBurst,
                perWorkspaceRequestsPerSecond,
                perWorkspaceBurst,
                System::nanoTime,
                TimeUnit.NANOSECONDS::sleep);
    }

    static KeyedPermitLimiter createPostAuthLimiter(double globalRequestsPerSecond,
                                                    int globalBurst,
                                                    double perWorkspaceRequestsPerSecond,
                                                    int perWorkspaceBurst,
                                                    LongSupplier nanoClock) {
        return createPostAuthLimiter(
                globalRequestsPerSecond,
                globalBurst,
                perWorkspaceRequestsPerSecond,
                perWorkspaceBurst,
                nanoClock,
                TimeUnit.NANOSECONDS::sleep);
    }

    static KeyedPermitLimiter createPostAuthLimiter(double globalRequestsPerSecond,
                                                    int globalBurst,
                                                    double perWorkspaceRequestsPerSecond,
                                                    int perWorkspaceBurst,
                                                    LongSupplier nanoClock,
                                                    NanoSleeper sleeper) {
        SubRateLimit wsLimit = resolveSubRateLimit(
                globalRequestsPerSecond, globalBurst, perWorkspaceRequestsPerSecond, perWorkspaceBurst);
        Objects.requireNonNull(nanoClock, NANO_CLOCK_NULL_MSG);
        Objects.requireNonNull(sleeper, SLEEPER_NULL_MSG);

        int resolvedGlobalBurst = resolveBurst(globalRequestsPerSecond, globalBurst);
        TokenBucket globalBucket = new TokenBucket(globalRequestsPerSecond, resolvedGlobalBurst, nanoClock, sleeper);
        LoadingCache<String, TokenBucket> wsBuckets = Caffeine.newBuilder()
                .maximumSize(MAX_CACHED_KEYS)
                .expireAfterAccess(BUCKET_IDLE_EXPIRATION)
                .ticker(nanoClock::getAsLong)
                .build(_ -> new TokenBucket(wsLimit.requestsPerSecond(), wsLimit.burst(), nanoClock, sleeper));

        return (key, timeout) -> {
            long startNanos = nanoClock.getAsLong();
            String bucketKey = (key != null && !key.isEmpty()) ? key : GLOBAL_FALLBACK_KEY;
            TokenBucket wsBucket = Objects.requireNonNull(wsBuckets.get(bucketKey));
            AcquireResult wsResult = wsBucket.tryAcquire(timeout);
            if (!wsResult.allowed()) {
                return wsResult;
            }

            Duration remainingTimeout = remainingTimeout(timeout, startNanos, nanoClock);
            AcquireResult globalResult = globalBucket.tryAcquire(remainingTimeout);
            if (!globalResult.allowed()) {
                wsBucket.refund();
                return globalResult;
            }
            return AcquireResult.ALLOWED;
        };
    }

    public static UnauthenticatedLookupLimiter createUnauthenticatedLookupLimiter(Environment environment) {
        return createUnauthenticatedLookupLimiter(environment, System::nanoTime, TimeUnit.NANOSECONDS::sleep);
    }

    static UnauthenticatedLookupLimiter createUnauthenticatedLookupLimiter(Environment environment,
                                                                           LongSupplier nanoClock) {
        return createUnauthenticatedLookupLimiter(environment, nanoClock, TimeUnit.NANOSECONDS::sleep);
    }

    static UnauthenticatedLookupLimiter createUnauthenticatedLookupLimiter(Environment environment,
                                                                           LongSupplier nanoClock,
                                                                           NanoSleeper sleeper) {
        Objects.requireNonNull(environment, "environment must not be null");
        Binder binder = Binder.get(environment);
        double globalRps = binder.bind("app.rate-limit.requests-per-second", Double.class).orElse(200.0);
        int globalBurst = binder.bind("app.rate-limit.burst", Integer.class).orElse(0);
        double unauthRps = binder.bind("app.rate-limit.unauthenticated-requests-per-second", Double.class).orElse(0.0);
        int unauthBurst = binder.bind("app.rate-limit.unauthenticated-burst", Integer.class).orElse(0);
        double perIpUnauthRps = binder.bind(
                "app.rate-limit.per-ip-unauthenticated-requests-per-second", Double.class).orElse(0.0);
        int perIpUnauthBurst = binder.bind(
                "app.rate-limit.per-ip-unauthenticated-burst", Integer.class).orElse(0);
        String trustedProxies = binder.bind("app.rate-limit.trusted-proxies", String.class).orElse("");
        String trustedCloudflareProxies = binder.bind(
                "app.rate-limit.trusted-cloudflare-proxies", String.class).orElse("");
        Duration waitTimeout = binder.bind("app.rate-limit.wait-timeout", Duration.class).orElse(DEFAULT_WAIT_TIMEOUT);

        SubRateLimit podLimit = resolveSubRateLimit(globalRps, globalBurst, unauthRps, unauthBurst);
        SubRateLimit perIpLimit = resolveSubRateLimit(
                podLimit.requestsPerSecond(),
                podLimit.burst(),
                perIpUnauthRps,
                perIpUnauthBurst);
        return createUnauthenticatedLookupLimiter(
                podLimit,
                perIpLimit,
                ClientIpResolver.parseTrustedProxies(trustedProxies),
                ClientIpResolver.parseTrustedProxies(trustedCloudflareProxies),
                waitTimeout,
                nanoClock,
                sleeper);
    }

    public static UnauthenticatedLookupLimiter createUnauthenticatedLookupLimiter(
            double globalRequestsPerSecond,
            int globalBurst,
            double unauthenticatedRequestsPerSecond,
            int unauthenticatedBurst,
            double perIpUnauthenticatedRequestsPerSecond,
            int perIpUnauthenticatedBurst,
            Duration waitTimeout) {
        SubRateLimit podLimit = resolveSubRateLimit(
                globalRequestsPerSecond,
                globalBurst,
                unauthenticatedRequestsPerSecond,
                unauthenticatedBurst);
        SubRateLimit perIpLimit = resolveSubRateLimit(
                podLimit.requestsPerSecond(),
                podLimit.burst(),
                perIpUnauthenticatedRequestsPerSecond,
                perIpUnauthenticatedBurst);
        return createUnauthenticatedLookupLimiter(
                podLimit,
                perIpLimit,
                List.of(),
                List.of(),
                waitTimeout,
                System::nanoTime,
                TimeUnit.NANOSECONDS::sleep);
    }

    static UnauthenticatedLookupLimiter createUnauthenticatedLookupLimiter(
            SubRateLimit podLimit,
            SubRateLimit perIpLimit,
            Duration waitTimeout,
            LongSupplier nanoClock) {
        return createUnauthenticatedLookupLimiter(
                podLimit,
                perIpLimit,
                List.of(),
                List.of(),
                waitTimeout,
                nanoClock,
                TimeUnit.NANOSECONDS::sleep);
    }

    static UnauthenticatedLookupLimiter createUnauthenticatedLookupLimiter(
            SubRateLimit podLimit,
            SubRateLimit perIpLimit,
            List<IpAddressMatcher> trustedProxies,
            List<IpAddressMatcher> trustedCloudflareProxies,
            Duration waitTimeout,
            LongSupplier nanoClock,
            NanoSleeper sleeper) {
        Objects.requireNonNull(podLimit, "podLimit must not be null");
        Objects.requireNonNull(perIpLimit, "perIpLimit must not be null");
        Objects.requireNonNull(nanoClock, NANO_CLOCK_NULL_MSG);
        Objects.requireNonNull(sleeper, SLEEPER_NULL_MSG);

        Duration effectiveWaitTimeout = resolveWaitTimeout(waitTimeout);
        List<IpAddressMatcher> effectiveTrustedProxies = trustedProxies != null
                ? List.copyOf(trustedProxies)
                : List.of();
        List<IpAddressMatcher> effectiveCloudflareProxies = trustedCloudflareProxies != null
                ? List.copyOf(trustedCloudflareProxies)
                : List.of();

        TokenBucket podLookupBucket = new TokenBucket(
                podLimit.requestsPerSecond(), podLimit.burst(), nanoClock, sleeper);
        LoadingCache<String, TokenBucket> perIpLookupBuckets = Caffeine.newBuilder()
                .maximumSize(MAX_CACHED_KEYS)
                .expireAfterAccess(BUCKET_IDLE_EXPIRATION)
                .ticker(nanoClock::getAsLong)
                .build(_ -> new TokenBucket(
                        perIpLimit.requestsPerSecond(), perIpLimit.burst(), nanoClock, sleeper));
        Cache<String, Boolean> verifiedTokenHashes = Caffeine.newBuilder()
                .maximumSize(MAX_VERIFIED_TOKENS)
                .expireAfterAccess(VERIFIED_TOKEN_IDLE_EXPIRATION)
                .ticker(nanoClock::getAsLong)
                .build();

        return new DefaultUnauthenticatedLookupLimiter(
                perIpLookupBuckets,
                podLookupBucket,
                verifiedTokenHashes,
                effectiveTrustedProxies,
                effectiveCloudflareProxies,
                effectiveWaitTimeout,
                nanoClock);
    }

    public static KeyedPermitLimiter createKeyedLimiter(double requestsPerSecond, int configuredBurst) {
        return createKeyedLimiter(requestsPerSecond, configuredBurst, System::nanoTime, TimeUnit.NANOSECONDS::sleep);
    }

    static KeyedPermitLimiter createKeyedLimiter(double requestsPerSecond,
                                                 int configuredBurst,
                                                 LongSupplier nanoClock) {
        return createKeyedLimiter(requestsPerSecond, configuredBurst, nanoClock, TimeUnit.NANOSECONDS::sleep);
    }

    static KeyedPermitLimiter createKeyedLimiter(double requestsPerSecond,
                                                 int configuredBurst,
                                                 LongSupplier nanoClock,
                                                 NanoSleeper sleeper) {
        validatePositiveFiniteRate(requestsPerSecond, "requestsPerSecond");
        Objects.requireNonNull(nanoClock, NANO_CLOCK_NULL_MSG);
        Objects.requireNonNull(sleeper, SLEEPER_NULL_MSG);

        int resolvedBurst = resolveBurst(requestsPerSecond, configuredBurst);
        LoadingCache<String, TokenBucket> buckets = Caffeine.newBuilder()
                .maximumSize(MAX_CACHED_KEYS)
                .expireAfterAccess(BUCKET_IDLE_EXPIRATION)
                .ticker(nanoClock::getAsLong)
                .build(_ -> new TokenBucket(requestsPerSecond, resolvedBurst, nanoClock, sleeper));
        return (key, timeout) -> {
            String bucketKey = (key != null && !key.isEmpty()) ? key : GLOBAL_FALLBACK_KEY;
            TokenBucket bucket = Objects.requireNonNull(buckets.get(bucketKey));
            return bucket.tryAcquire(timeout);
        };
    }

    private static Duration remainingTimeout(Duration timeout, long startNanos, LongSupplier nanoClock) {
        if (timeout == null || timeout.isZero() || timeout.isNegative()) {
            return Duration.ZERO;
        }
        long elapsed = Math.max(0L, nanoClock.getAsLong() - startNanos);
        long remainingNanos = timeout.toNanos() - elapsed;
        return remainingNanos > 0L ? Duration.ofNanos(remainingNanos) : Duration.ZERO;
    }

    static void validatePositiveFiniteRate(double rate, String name) {
        if (!Double.isFinite(rate) || rate <= 0.0) {
            throw new IllegalArgumentException(name + " must be a finite positive number");
        }
    }

    static SubRateLimit resolveSubRateLimit(double parentRequestsPerSecond,
                                            int parentBurst,
                                            double subRequestsPerSecond,
                                            int subBurst) {
        validatePositiveFiniteRate(parentRequestsPerSecond, "requestsPerSecond");
        if (!Double.isFinite(subRequestsPerSecond)) {
            throw new IllegalArgumentException("subRequestsPerSecond must be a finite number");
        }

        int resolvedParentBurst = resolveBurst(parentRequestsPerSecond, parentBurst);
        boolean hasExplicitSubRps = subRequestsPerSecond > 0.0;
        double effectiveRps = hasExplicitSubRps
                ? subRequestsPerSecond
                : (parentRequestsPerSecond / DEFAULT_SUB_DIVISOR);

        int effectiveBurst;
        if (subBurst > 0) {
            effectiveBurst = subBurst;
        } else if (hasExplicitSubRps) {
            effectiveBurst = resolveBurst(effectiveRps, 0);
        } else {
            effectiveBurst = Math.max(1, (int) Math.ceil(resolvedParentBurst / DEFAULT_SUB_DIVISOR));
        }
        return new SubRateLimit(effectiveRps, effectiveBurst);
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

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return RequestPaths.isActuatorPath(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        request.setAttribute(ScimRequestMetricAttributes.THROTTLED, ScimRequestMetricAttributes.THROTTLED_NO);

        String clientIpKey = ClientIpResolver.extractClientIpKey(
                request, trustedProxies, trustedCloudflareProxies);
        request.setAttribute(RESOLVED_CLIENT_IP_KEY_ATTRIBUTE, clientIpKey);
        AcquireResult result = permitLimiter.tryAcquire(clientIpKey, waitTimeout);
        if (!result.allowed()) {
            request.setAttribute(ScimRequestMetricAttributes.THROTTLED, ScimRequestMetricAttributes.THROTTLED_YES);
            ScimFilterErrorWriter.writeScimError(
                    response,
                    objectMapper,
                    HttpStatus.TOO_MANY_REQUESTS.value(),
                    null,
                    CAPACITY_ERROR_DETAIL,
                    "Retry-After",
                    Long.toString(Math.max(1L, result.retryAfterSeconds())));
            return;
        }

        chain.doFilter(request, response);
    }

    public record AcquireResult(boolean allowed, long retryAfterSeconds) {
        public static final AcquireResult ALLOWED = new AcquireResult(true, 0L);

        public static AcquireResult rejected(long retryAfterSeconds) {
            return new AcquireResult(false, Math.max(1L, retryAfterSeconds));
        }
    }

    record SubRateLimit(double requestsPerSecond, int burst) {
    }

    @FunctionalInterface
    public interface KeyedPermitLimiter {
        AcquireResult tryAcquire(String key, Duration timeout);
    }

    public interface UnauthenticatedLookupLimiter {
        UnauthenticatedLookupLimiter NOOP = new UnauthenticatedLookupLimiter() {
            @Override
            public boolean isKnownActiveToken(String tokenCacheKey) {
                return false;
            }

            @Override
            public AcquireResult tryAcquireLookupPermit(HttpServletRequest request) {
                return AcquireResult.ALLOWED;
            }

            @Override
            public void onValidTokenLookup(HttpServletRequest request, String tokenCacheKey, boolean refundLookupPermit) {
                // No-op when rate limiting is disabled
            }

            @Override
            public void evictToken(String tokenCacheKey) {
                // No-op when rate limiting is disabled
            }
        };

        boolean isKnownActiveToken(String tokenCacheKey);

        AcquireResult tryAcquireLookupPermit(HttpServletRequest request);

        void onValidTokenLookup(HttpServletRequest request, String tokenCacheKey, boolean refundLookupPermit);

        void evictToken(String tokenCacheKey);
    }

    private record DefaultUnauthenticatedLookupLimiter(
            LoadingCache<String, TokenBucket> perIpLookupBuckets,
            TokenBucket podLookupBucket,
            Cache<String, Boolean> verifiedTokenHashes,
            List<IpAddressMatcher> trustedProxies,
            List<IpAddressMatcher> trustedCloudflareProxies,
            Duration waitTimeout,
            LongSupplier nanoClock) implements UnauthenticatedLookupLimiter {

        @Override
        public boolean isKnownActiveToken(String tokenCacheKey) {
            return tokenCacheKey != null && verifiedTokenHashes.getIfPresent(tokenCacheKey) != null;
        }

        @Override
        public AcquireResult tryAcquireLookupPermit(HttpServletRequest request) {
            long startNanos = nanoClock.getAsLong();
            TokenBucket ipBucket = Objects.requireNonNull(perIpLookupBuckets.get(resolveClientIpKey(request)));
            AcquireResult ipResult = ipBucket.tryAcquire(waitTimeout);
            if (!ipResult.allowed()) {
                return ipResult;
            }

            Duration remaining = remainingTimeout(waitTimeout, startNanos, nanoClock);
            AcquireResult podResult = podLookupBucket.tryAcquire(remaining);
            if (!podResult.allowed()) {
                ipBucket.refund();
                return podResult;
            }
            return AcquireResult.ALLOWED;
        }

        @Override
        public void onValidTokenLookup(HttpServletRequest request, String tokenCacheKey, boolean refundLookupPermit) {
            if (tokenCacheKey != null) {
                verifiedTokenHashes.put(tokenCacheKey, Boolean.TRUE);
            }
            if (refundLookupPermit) {
                TokenBucket ipBucket = perIpLookupBuckets.getIfPresent(resolveClientIpKey(request));
                if (ipBucket != null) {
                    ipBucket.refund();
                }
                podLookupBucket.refund();
            }
        }

        @Override
        public void evictToken(String tokenCacheKey) {
            if (tokenCacheKey != null) {
                verifiedTokenHashes.invalidate(tokenCacheKey);
            }
        }

        private String resolveClientIpKey(HttpServletRequest request) {
            if (request == null) {
                return GLOBAL_FALLBACK_KEY;
            }
            if (request.getAttribute(RESOLVED_CLIENT_IP_KEY_ATTRIBUTE) instanceof String cached && !cached.isEmpty()) {
                return cached;
            }
            String resolved = ClientIpResolver.extractClientIpKey(
                    request, trustedProxies, trustedCloudflareProxies);
            request.setAttribute(RESOLVED_CLIENT_IP_KEY_ATTRIBUTE, resolved);
            return resolved;
        }
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

        AcquireResult tryAcquire(Duration timeout) {
            if (timeout == null || timeout.isZero() || timeout.isNegative()) {
                return tryAcquireImmediate();
            }
            return tryAcquireWithTimeout(timeout.toNanos());
        }

        synchronized void refund() {
            refill(nanoClock.getAsLong());
            storedTokens = Math.min(maxTokens, storedTokens + 1.0);
        }

        private synchronized AcquireResult tryAcquireImmediate() {
            refill(nanoClock.getAsLong());
            if (storedTokens >= 1.0) {
                storedTokens -= 1.0;
                return AcquireResult.ALLOWED;
            }
            return AcquireResult.rejected(computeRetryAfterSeconds(1.0 - storedTokens));
        }

        private AcquireResult tryAcquireWithTimeout(long timeoutNanos) {
            long waitNanos;
            synchronized (this) {
                refill(nanoClock.getAsLong());
                if (storedTokens >= 1.0) {
                    storedTokens -= 1.0;
                    return AcquireResult.ALLOWED;
                }
                double deficit = 1.0 - storedTokens;
                double requiredNanos = (deficit * NANOS_PER_SECOND) / requestsPerSecond;
                if (requiredNanos > timeoutNanos) {
                    return AcquireResult.rejected(computeRetryAfterSeconds(deficit));
                }
                waitNanos = (long) Math.ceil(requiredNanos);
                storedTokens -= 1.0;
            }

            if (waitNanos <= 0L) {
                return AcquireResult.ALLOWED;
            }

            try {
                sleeper.sleepNanos(waitNanos);
                return AcquireResult.ALLOWED;
            } catch (InterruptedException _) {
                long retryAfter;
                synchronized (this) {
                    refill(nanoClock.getAsLong());
                    storedTokens = Math.min(maxTokens, storedTokens + 1.0);
                    retryAfter = computeRetryAfterSeconds(Math.max(0.0, 1.0 - storedTokens));
                }
                Thread.currentThread().interrupt();
                return AcquireResult.rejected(retryAfter);
            }
        }

        private long computeRetryAfterSeconds(double deficitTokens) {
            if (deficitTokens <= 0.0) {
                return 1L;
            }
            return Math.max(1L, (long) Math.ceil(deficitTokens / requestsPerSecond));
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
