package de.palsoftware.scim.server.impl.filter;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.util.StringUtils;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Resolves the pre-authentication rate-limit client-IP bucket key without triggering DNS lookups
 * and without mutating servlet request host/port metadata.
 * <p>
 * <b>Security invariant (why {@code server.forward-headers-strategy} / {@code RemoteIpValve} is NOT used):</b>
 * Spring Boot's Tomcat {@code RemoteIpValve} defaults {@code hostHeader = "X-Forwarded-Host"} and
 * {@code portHeader = "X-Forwarded-Port"}. When an in-cluster tunnel or ingress peer (e.g. {@code cloudflared}
 * on {@code 10.x.x.x}) matches {@code internalProxies}, enabling {@code RemoteIpValve} would overwrite
 * {@code request.getServerName()} and {@code request.getServerPort()} from client-supplied headers if edge
 * stripping were ever lost, violating {@code ScimBaseController}'s {@code meta.location} URL-poisoning defense.
 * Resolving the client IP strictly here via {@link IpAddressMatcher} and {@link InetAddress#ofLiteral(String)}
 * isolates rate-limit bucketing from {@code meta.location} generation and guarantees zero DNS lookups.
 */
final class ClientIpResolver {

    private ClientIpResolver() {
    }

    static List<IpAddressMatcher> parseTrustedProxies(String raw) {
        if (!StringUtils.hasText(raw)) {
            return List.of();
        }
        String[] parts = raw.split(",");
        List<IpAddressMatcher> matchers = new ArrayList<>(parts.length);
        for (String part : parts) {
            String item = part.trim();
            if (!item.isEmpty()) {
                matchers.add(parseTrustedProxyEntry(item));
            }
        }
        return List.copyOf(matchers);
    }

    private static IpAddressMatcher parseTrustedProxyEntry(String item) {
        int slashIdx = item.indexOf('/');
        if (slashIdx < 0) {
            InetAddress addr = parseIpLiteral(item);
            if (addr == null) {
                throw new IllegalArgumentException("Invalid trusted proxy IP: " + item);
            }
            return new IpAddressMatcher(addr.getHostAddress());
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
        return new IpAddressMatcher(addr.getHostAddress() + "/" + prefixBits);
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

    static String extractClientIpKey(HttpServletRequest request,
                                     List<IpAddressMatcher> trustedProxies,
                                     List<IpAddressMatcher> trustedCloudflareProxies) {
        if (request == null) {
            return ThrottlingFilter.GLOBAL_FALLBACK_KEY;
        }
        String remoteAddr = request.getRemoteAddr();
        if (!StringUtils.hasText(remoteAddr)) {
            return ThrottlingFilter.GLOBAL_FALLBACK_KEY;
        }
        String rawHost = splitHostFromRemoteAddr(remoteAddr.trim());
        InetAddress peerAddr = parseIpLiteral(rawHost);
        if (peerAddr == null) {
            return "ip:" + rawHost;
        }

        boolean cfTrusted = matchesAny(peerAddr, trustedCloudflareProxies);
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
            } catch (UnknownHostException e) {
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
                                                              List<IpAddressMatcher> trustedProxies,
                                                              List<IpAddressMatcher> trustedCloudflareProxies) {
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
                                             List<IpAddressMatcher> trustedProxies,
                                             List<IpAddressMatcher> trustedCloudflareProxies) {
        return matchesAny(hopAddr, trustedCloudflareProxies) || isTrustedProxyPeer(hopAddr, trustedProxies);
    }

    static boolean matchesAny(InetAddress addr, List<IpAddressMatcher> matchers) {
        if (addr == null || matchers == null || matchers.isEmpty()) {
            return false;
        }
        String canonicalIp = addr.getHostAddress();
        for (IpAddressMatcher matcher : matchers) {
            if (matcher.matches(canonicalIp)) {
                return true;
            }
        }
        return false;
    }

    static boolean isTrustedProxyPeer(InetAddress peerAddr, List<IpAddressMatcher> trustedProxies) {
        if (peerAddr == null) {
            return false;
        }
        if (trustedProxies != null && !trustedProxies.isEmpty()) {
            return matchesAny(peerAddr, trustedProxies);
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
}
