package de.palsoftware.scim.server.impl.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/**
 * Pre-authentication SCIM rate-limiting filter enforcing:
 * <ol>
 *   <li><b>Tier 1 (Per-Client-IP)</b>: Protects {@code WorkspaceTokenRepository} against
 *       unauthenticated random-UUID or invalid-token floods from a single client IP without
 *       letting unauthenticated callers exhaust any workspace's bucket.</li>
 *   <li><b>Tier 2 (Server-Wide Global Cap)</b>: Bounds aggregate RPS across all IPs and workspaces.</li>
 * </ol>
 */
@Component
@ConditionalOnProperty(prefix = "app.rate-limit", name = "enabled", havingValue = "true", matchIfMissing = false)
public class ThrottlingFilter extends OncePerRequestFilter {

    static final Duration DEFAULT_WAIT_TIMEOUT = Duration.ZERO;
    static final Duration MAX_WAIT_TIMEOUT = Duration.ofSeconds(5);
    static final int MAX_DEFAULT_BURST = 1_000;
    static final double DEFAULT_SUB_RPS = 250.0;
    static final int DEFAULT_SUB_MAX_BURST = 250;
    static final long MAX_CACHED_KEYS = 10_000L;
    static final Duration BUCKET_IDLE_EXPIRATION = Duration.ofMinutes(15);
    static final String GLOBAL_FALLBACK_KEY = "global";
    static final String CAPACITY_ERROR_DETAIL = "Too many requests. Try again later.";

    private final KeyedPermitLimiter permitLimiter;
    private final List<CidrBlock> trustedProxies;
    private final List<CidrBlock> trustedCloudflareProxies;
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
                parseTrustedProxies(configuredTrustedProxies),
                parseTrustedProxies(configuredTrustedCloudflareProxies),
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
                            List<CidrBlock> trustedProxies,
                            Duration waitTimeout,
                            ObjectMapper objectMapper) {
        this(permitLimiter, trustedProxies, List.of(), waitTimeout, objectMapper);
    }

    public ThrottlingFilter(KeyedPermitLimiter permitLimiter,
                            List<CidrBlock> trustedProxies,
                            List<CidrBlock> trustedCloudflareProxies,
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
        Objects.requireNonNull(nanoClock, "nanoClock must not be null");
        Objects.requireNonNull(sleeper, "sleeper must not be null");

        int resolvedGlobalBurst = resolveBurst(globalRequestsPerSecond, globalBurst);
        TokenBucket globalBucket = new TokenBucket(globalRequestsPerSecond, resolvedGlobalBurst, nanoClock, sleeper);
        LoadingCache<String, TokenBucket> ipBuckets = Caffeine.newBuilder()
                .maximumSize(MAX_CACHED_KEYS)
                .expireAfterAccess(BUCKET_IDLE_EXPIRATION)
                .build(_ -> new TokenBucket(ipLimit.requestsPerSecond(), ipLimit.burst(), nanoClock, sleeper));

        return (key, timeout) -> {
            long startNanos = nanoClock.getAsLong();
            String bucketKey = (key != null && !key.isEmpty()) ? key : GLOBAL_FALLBACK_KEY;
            TokenBucket ipBucket = Objects.requireNonNull(ipBuckets.get(bucketKey));
            AcquireResult ipResult = ipBucket.tryAcquire(timeout);
            if (!ipResult.allowed()) {
                return ipResult;
            }

            Duration remainingTimeout = remainingTimeout(timeout, startNanos, nanoClock);
            AcquireResult globalResult = globalBucket.tryAcquire(remainingTimeout);
            if (!globalResult.allowed()) {
                ipBucket.refund();
                return globalResult;
            }
            return AcquireResult.ALLOWED;
        };
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
        Objects.requireNonNull(nanoClock, "nanoClock must not be null");
        Objects.requireNonNull(sleeper, "sleeper must not be null");

        int resolvedBurst = resolveBurst(requestsPerSecond, configuredBurst);
        LoadingCache<String, TokenBucket> buckets = Caffeine.newBuilder()
                .maximumSize(MAX_CACHED_KEYS)
                .expireAfterAccess(BUCKET_IDLE_EXPIRATION)
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

    static SubRateLimit resolveSubRateLimit(double globalRequestsPerSecond,
                                            int globalBurst,
                                            double subRequestsPerSecond,
                                            int subBurst) {
        validatePositiveFiniteRate(globalRequestsPerSecond, "requestsPerSecond");
        if (!Double.isFinite(subRequestsPerSecond)) {
            throw new IllegalArgumentException("subRequestsPerSecond must be a finite number");
        }

        int resolvedGlobalBurst = resolveBurst(globalRequestsPerSecond, globalBurst);
        boolean hasExplicitSubRps = subRequestsPerSecond > 0.0;
        double effectiveRps = hasExplicitSubRps
                ? subRequestsPerSecond
                : Math.min(globalRequestsPerSecond, DEFAULT_SUB_RPS);

        int effectiveBurst;
        if (subBurst > 0) {
            effectiveBurst = subBurst;
        } else if (hasExplicitSubRps) {
            effectiveBurst = resolveBurst(effectiveRps, 0);
        } else {
            effectiveBurst = Math.max(1, Math.min(resolvedGlobalBurst, DEFAULT_SUB_MAX_BURST));
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

    public static List<CidrBlock> parseTrustedProxies(String raw) {
        if (!StringUtils.hasText(raw)) {
            return List.of();
        }
        String[] parts = raw.split(",");
        List<CidrBlock> blocks = new ArrayList<>(parts.length);
        for (String part : parts) {
            String item = part.trim();
            if (!item.isEmpty()) {
                blocks.add(parseTrustedProxyEntry(item));
            }
        }
        return List.copyOf(blocks);
    }

    private static CidrBlock parseTrustedProxyEntry(String item) {
        int slashIdx = item.indexOf('/');
        if (slashIdx < 0) {
            InetAddress addr = parseIpLiteral(item);
            if (addr == null) {
                throw new IllegalArgumentException("Invalid trusted proxy IP: " + item);
            }
            byte[] addrBytes = addr.getAddress();
            return new CidrBlock(addrBytes, addrBytes.length * 8);
        }
        if (item.indexOf('/', slashIdx + 1) >= 0) {
            throw new IllegalArgumentException("Invalid trusted proxy CIDR: " + item);
        }
        String ipPart = item.substring(0, slashIdx).trim();
        InetAddress addr = parseIpLiteral(ipPart);
        if (addr == null) {
            throw new IllegalArgumentException("Invalid trusted proxy CIDR address: " + item);
        }
        int prefixBits = parseCidrPrefixLength(item, item.substring(slashIdx + 1).trim(), ipPart, addr);
        return new CidrBlock(addr.getAddress(), prefixBits);
    }

    private static int parseCidrPrefixLength(String fullItem, String prefixPart, String ipPart, InetAddress addr) {
        int prefixBits;
        try {
            prefixBits = Integer.parseInt(prefixPart);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid trusted proxy CIDR prefix: " + fullItem, e);
        }
        // Unmap IPv4-mapped IPv6 CIDR (e.g. ::ffff:192.0.2.0/120 -> 192.0.2.0/24)
        if (ipPart.indexOf(':') >= 0 && addr instanceof Inet4Address && prefixBits >= 96 && prefixBits <= 128) {
            prefixBits -= 96;
        }
        int totalBits = addr.getAddress().length * 8;
        if (prefixBits < 0 || prefixBits > totalBits) {
            throw new IllegalArgumentException("Invalid trusted proxy CIDR prefix length: " + fullItem);
        }
        return prefixBits;
    }

    static String extractClientIpKey(HttpServletRequest request, List<CidrBlock> trustedProxies) {
        return extractClientIpKey(request, trustedProxies, List.of());
    }

    static String extractClientIpKey(HttpServletRequest request,
                                     List<CidrBlock> trustedProxies,
                                     List<CidrBlock> trustedCloudflareProxies) {
        if (request == null) {
            return GLOBAL_FALLBACK_KEY;
        }
        String remoteAddr = request.getRemoteAddr();
        if (!StringUtils.hasText(remoteAddr)) {
            return GLOBAL_FALLBACK_KEY;
        }
        String rawHost = splitHostFromRemoteAddr(remoteAddr.trim());
        if (rawHost.isEmpty()) {
            return GLOBAL_FALLBACK_KEY;
        }

        InetAddress peerAddr = parseIpLiteral(rawHost);
        if (peerAddr == null) {
            return "ip:" + rawHost;
        }

        boolean cfTrusted = matchesAnyCidr(peerAddr, trustedCloudflareProxies);
        if (cfTrusted) {
            InetAddress cfAddr = extractSingleCfConnectingIp(request);
            if (cfAddr != null) {
                return formatClientIpKey(cfAddr);
            }
        }

        if (cfTrusted || isTrustedProxyPeer(peerAddr, trustedProxies)) {
            InetAddress resolved = resolveClientFromXForwardedFor(
                    request, peerAddr, trustedProxies, trustedCloudflareProxies);
            return formatClientIpKey(resolved);
        }

        return formatClientIpKey(peerAddr);
    }

    static String formatClientIpKey(InetAddress addr) {
        if (addr instanceof Inet4Address) {
            return "ip:" + addr.getHostAddress();
        }
        byte[] bytes = addr.getAddress();
        if (bytes.length == 16) {
            byte[] masked64 = new byte[16];
            System.arraycopy(bytes, 0, masked64, 0, 8);
            try {
                return "ip:" + InetAddress.getByAddress(masked64).getHostAddress() + "/64";
            } catch (java.net.UnknownHostException e) {
                throw new IllegalStateException("Unexpected 16-byte IPv6 address length error", e);
            }
        }
        return "ip:" + addr.getHostAddress();
    }

    private static InetAddress extractSingleCfConnectingIp(HttpServletRequest request) {
        Enumeration<String> values = request.getHeaders("CF-Connecting-IP");
        if (values == null || !values.hasMoreElements()) {
            return null;
        }
        String first = values.nextElement();
        if (values.hasMoreElements() || first == null || first.indexOf(',') >= 0) {
            return null;
        }
        return parseIpLiteral(first);
    }

    private static InetAddress resolveClientFromXForwardedFor(HttpServletRequest request,
                                                              InetAddress peerAddr,
                                                              List<CidrBlock> trustedProxies,
                                                              List<CidrBlock> trustedCloudflareProxies) {
        InetAddress lastTrustedHop = null;
        for (String token : collectXffTokensRightToLeft(request)) {
            InetAddress hopAddr = parseIpLiteral(token);
            if (hopAddr == null) {
                break;
            }
            if (!isTrustedProxyHop(hopAddr, trustedProxies, trustedCloudflareProxies)) {
                return hopAddr;
            }
            lastTrustedHop = hopAddr;
        }
        return lastTrustedHop != null ? lastTrustedHop : peerAddr;
    }

    private static List<String> collectXffTokensRightToLeft(HttpServletRequest request) {
        Enumeration<String> values = request.getHeaders("X-Forwarded-For");
        if (values == null || !values.hasMoreElements()) {
            return List.of();
        }
        List<String> headers = new ArrayList<>(2);
        while (values.hasMoreElements()) {
            String h = values.nextElement();
            if (h != null) {
                headers.add(h);
            }
        }
        List<String> tokens = new ArrayList<>(4);
        for (int h = headers.size() - 1; h >= 0; h--) {
            appendCommaTokensRightToLeft(headers.get(h), tokens);
        }
        return tokens;
    }

    private static void appendCommaTokensRightToLeft(String header, List<String> out) {
        int end = header.length();
        while (end > 0) {
            int commaIdx = header.lastIndexOf(',', end - 1);
            String token = header.substring(commaIdx + 1, end).trim();
            if (!token.isEmpty()) {
                out.add(token);
            }
            end = commaIdx;
        }
    }

    private static boolean isTrustedProxyHop(InetAddress hopAddr,
                                             List<CidrBlock> trustedProxies,
                                             List<CidrBlock> trustedCloudflareProxies) {
        return matchesAnyCidr(hopAddr, trustedCloudflareProxies) || isTrustedProxyPeer(hopAddr, trustedProxies);
    }

    private static boolean matchesAnyCidr(InetAddress addr, List<CidrBlock> blocks) {
        if (addr == null || blocks == null || blocks.isEmpty()) {
            return false;
        }
        for (CidrBlock block : blocks) {
            if (block.contains(addr)) {
                return true;
            }
        }
        return false;
    }

    static boolean isTrustedProxyPeer(InetAddress peerAddr, List<CidrBlock> trustedProxies) {
        if (peerAddr == null) {
            return false;
        }
        if (trustedProxies != null && !trustedProxies.isEmpty()) {
            return matchesAnyCidr(peerAddr, trustedProxies);
        }
        return peerAddr.isLoopbackAddress()
                || peerAddr.isSiteLocalAddress()
                || peerAddr.isLinkLocalAddress()
                || isIpv6UniqueLocal(peerAddr);
    }

    private static boolean isIpv6UniqueLocal(InetAddress addr) {
        if (addr instanceof Inet6Address) {
            byte[] bytes = addr.getAddress();
            return bytes.length == 16 && (bytes[0] & 0xFE) == 0xFC;
        }
        return false;
    }

    static String splitHostFromRemoteAddr(String addr) {
        if (addr.isEmpty()) {
            return "";
        }
        if (addr.charAt(0) == '[') {
            int closeIdx = addr.indexOf(']');
            if (closeIdx > 1) {
                if (closeIdx == addr.length() - 1) {
                    return addr.substring(1, closeIdx);
                }
                if (addr.charAt(closeIdx + 1) == ':' && isValidPort(addr, closeIdx + 2)) {
                    return addr.substring(1, closeIdx);
                }
            }
            return addr;
        }
        int firstColon = addr.indexOf(':');
        if (firstColon > 0 && addr.indexOf(':', firstColon + 1) < 0 && isValidPort(addr, firstColon + 1)) {
            return addr.substring(0, firstColon);
        }
        return addr;
    }

    private static boolean isValidPort(String s, int startIdx) {
        int len = s.length() - startIdx;
        if (len <= 0 || len > 5) {
            return false;
        }
        int port = 0;
        for (int i = startIdx; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
            port = port * 10 + (c - '0');
        }
        return port >= 1 && port <= 65535;
    }

    /**
     * Parses numeric IPv4 and IPv6 literals using {@link InetAddress#ofLiteral(String)}
     * with strict dotted-quad validation and zero DNS lookups.
     */
    static InetAddress parseIpLiteral(String raw) {
        String s = normalizeIpLiteralInput(raw);
        if (s == null || !hasValidIpv4SegmentIfPresent(s)) {
            return null;
        }
        try {
            return InetAddress.ofLiteral(s);
        } catch (IllegalArgumentException _) {
            return null;
        }
    }

    private static String normalizeIpLiteralInput(String raw) {
        if (raw == null) {
            return null;
        }
        String s = raw.trim();
        if (s.isEmpty()) {
            return null;
        }
        if (s.charAt(0) == '[' && s.charAt(s.length() - 1) == ']' && s.length() > 2) {
            String inner = s.substring(1, s.length() - 1);
            if (inner.indexOf(':') < 0) {
                return null;
            }
            s = inner;
        }
        int pctIdx = s.indexOf('%');
        if (pctIdx >= 0) {
            if (pctIdx == 0 || pctIdx == s.length() - 1) {
                return null;
            }
            int colonIdx = s.indexOf(':');
            return (colonIdx >= 0 && colonIdx < pctIdx) ? s.substring(0, pctIdx) : null;
        }
        return s;
    }

    private static boolean hasValidIpv4SegmentIfPresent(String s) {
        int lastColon = s.lastIndexOf(':');
        if (lastColon < 0) {
            return isStrictIpv4Literal(s);
        }
        if (s.indexOf('.', lastColon + 1) >= 0) {
            return isStrictIpv4Literal(s.substring(lastColon + 1));
        }
        return true;
    }

    private static boolean isStrictIpv4Literal(String s) {
        int len = s.length();
        if (len < 7 || len > 15) {
            return false;
        }
        int start = 0;
        for (int octet = 0; octet < 3; octet++) {
            int dot = s.indexOf('.', start);
            if (dot <= start || !isValidDecimalOctet(s, start, dot)) {
                return false;
            }
            start = dot + 1;
        }
        return s.indexOf('.', start) < 0 && isValidDecimalOctet(s, start, len);
    }

    private static boolean isValidDecimalOctet(String s, int start, int end) {
        int digitCount = end - start;
        if (digitCount <= 0 || digitCount > 3 || (digitCount > 1 && s.charAt(start) == '0')) {
            return false;
        }
        int val = 0;
        for (int i = start; i < end; i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
            val = val * 10 + (c - '0');
        }
        return val <= 255;
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

        String clientIpKey = extractClientIpKey(request, trustedProxies, trustedCloudflareProxies);
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

    public static final class CidrBlock {
        private final byte[] maskedNetwork;
        private final int prefixBits;

        CidrBlock(byte[] rawAddress, int prefixBits) {
            this.maskedNetwork = rawAddress.clone();
            this.prefixBits = prefixBits;
            int fullBytes = prefixBits / 8;
            int remBits = prefixBits % 8;
            if (remBits > 0 && fullBytes < maskedNetwork.length) {
                int mask = (0xFF << (8 - remBits)) & 0xFF;
                maskedNetwork[fullBytes] = (byte) (maskedNetwork[fullBytes] & mask);
                fullBytes++;
            }
            for (int i = fullBytes; i < maskedNetwork.length; i++) {
                maskedNetwork[i] = 0;
            }
        }

        public boolean contains(InetAddress candidate) {
            if (candidate == null) {
                return false;
            }
            byte[] candBytes = candidate.getAddress();
            if (candBytes.length != maskedNetwork.length) {
                return false;
            }
            int fullBytes = prefixBits / 8;
            for (int i = 0; i < fullBytes; i++) {
                if (candBytes[i] != maskedNetwork[i]) {
                    return false;
                }
            }
            int remBits = prefixBits % 8;
            if (remBits > 0) {
                int mask = (0xFF << (8 - remBits)) & 0xFF;
                return (candBytes[fullBytes] & mask) == (maskedNetwork[fullBytes] & 0xFF);
            }
            return true;
        }
    }

    @FunctionalInterface
    public interface KeyedPermitLimiter {
        AcquireResult tryAcquire(String key, Duration timeout);
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
