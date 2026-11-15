package de.palsoftware.scim.server.impl.filter;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientIpResolverTest {

    private static String extractClientIpKey(HttpServletRequest request, List<IpAddressMatcher> trustedProxies) {
        return ClientIpResolver.extractClientIpKey(request, trustedProxies, List.of());
    }

    @Test
    void extractClientIpKey_HandlesNullBlankAndPublicPeersWithoutTrustingForwardedHeaders() {
        assertThat(extractClientIpKey(null, List.of()))
                .isEqualTo(ThrottlingFilter.GLOBAL_FALLBACK_KEY);

        MockHttpServletRequest blankRemote = new MockHttpServletRequest();
        blankRemote.setRemoteAddr("   ");
        assertThat(extractClientIpKey(blankRemote, List.of()))
                .isEqualTo(ThrottlingFilter.GLOBAL_FALLBACK_KEY);

        // Public IPv4 peer MUST ignore spoofed CF-Connecting-IP and X-Forwarded-For when trustedProxies is empty
        MockHttpServletRequest publicPeer = new MockHttpServletRequest();
        publicPeer.setRemoteAddr("198.51.100.99:54321");
        publicPeer.addHeader("CF-Connecting-IP", "203.0.113.1");
        publicPeer.addHeader("X-Forwarded-For", "203.0.113.2");
        assertThat(extractClientIpKey(publicPeer, List.of()))
                .isEqualTo("ip:198.51.100.99");

        // Public IPv6 peer ignores forwarded headers and keys by /64 prefix
        MockHttpServletRequest publicV6Peer = new MockHttpServletRequest();
        publicV6Peer.setRemoteAddr("[2001:db8:1111:2222:aaaa:bbbb:cccc:5]:8443");
        publicV6Peer.addHeader("X-Forwarded-For", "203.0.113.2");
        assertThat(extractClientIpKey(publicV6Peer, List.of()))
                .isEqualTo("ip:2001:db8:1111:2222:0:0:0:0/64");

        // IPv4-mapped IPv6 literal unmaps to /32 IPv4 key (never /64 IPv6!)
        MockHttpServletRequest mappedV4Peer = new MockHttpServletRequest();
        mappedV4Peer.setRemoteAddr("::ffff:192.0.2.5");
        assertThat(extractClientIpKey(mappedV4Peer, List.of()))
                .isEqualTo("ip:192.0.2.5");
    }

    @Test
    void extractClientIpKey_DefaultPrivatePeersAndCloudflareProxyGatingWorkAccurately() {
        // Default empty trustedProxies trusts loopback, RFC1918, IPv6 ULA (fc00::/7), and link-local for XFF
        for (String trustedPeer : List.of("127.0.0.1", "::1", "10.1.2.3", "172.16.5.4", "192.168.1.1",
                "fd12:3456:789a::1", "fc00::1", "169.254.10.20", "fe80::1%en0")) {
            MockHttpServletRequest proxyReq = new MockHttpServletRequest();
            proxyReq.setRemoteAddr(trustedPeer);
            proxyReq.addHeader("X-Forwarded-For", "198.51.100.50, 203.0.113.77");
            assertThat(extractClientIpKey(proxyReq, List.of()))
                    .as("Peer %s should resolve rightmost untrusted XFF hop", trustedPeer)
                    .isEqualTo("ip:203.0.113.77");
        }

        // CF-Connecting-IP MUST be ignored when trusted-cloudflare-proxies is empty (prevents Nginx/ALB bypass!)
        MockHttpServletRequest spoofedCfBehindAlb = new MockHttpServletRequest();
        spoofedCfBehindAlb.setRemoteAddr("10.0.0.2");
        spoofedCfBehindAlb.addHeader("CF-Connecting-IP", "203.0.113.88");
        spoofedCfBehindAlb.addHeader("X-Forwarded-For", "198.51.100.1");
        assertThat(ClientIpResolver.extractClientIpKey(spoofedCfBehindAlb, List.of(), List.of()))
                .isEqualTo("ip:198.51.100.1");

        // When peer matches trusted-cloudflare-proxies, valid single CF-Connecting-IP is used;
        // duplicate, comma-separated, or missing CF-Connecting-IP falls back to X-Forwarded-For
        List<IpAddressMatcher> cfProxies = ClientIpResolver.parseTrustedProxies("173.245.48.0/20, 2400:cb00::/32");
        MockHttpServletRequest validCfReq = new MockHttpServletRequest();
        validCfReq.setRemoteAddr("173.245.48.12");
        validCfReq.addHeader("CF-Connecting-IP", "203.0.113.88");
        validCfReq.addHeader("X-Forwarded-For", "198.51.100.1");
        assertThat(ClientIpResolver.extractClientIpKey(validCfReq, List.of(), cfProxies))
                .isEqualTo("ip:203.0.113.88");

        MockHttpServletRequest multiCfReq = new MockHttpServletRequest();
        multiCfReq.setRemoteAddr("173.245.48.12");
        multiCfReq.addHeader("CF-Connecting-IP", "203.0.113.1");
        multiCfReq.addHeader("CF-Connecting-IP", "203.0.113.2");
        multiCfReq.addHeader("X-Forwarded-For", "198.51.100.44");
        assertThat(ClientIpResolver.extractClientIpKey(multiCfReq, List.of(), cfProxies))
                .isEqualTo("ip:198.51.100.44");

        MockHttpServletRequest commaCfReq = new MockHttpServletRequest();
        commaCfReq.setRemoteAddr("173.245.48.12");
        commaCfReq.addHeader("CF-Connecting-IP", "203.0.113.1, 203.0.113.2");
        commaCfReq.addHeader("X-Forwarded-For", "198.51.100.45");
        assertThat(ClientIpResolver.extractClientIpKey(commaCfReq, List.of(), cfProxies))
                .isEqualTo("ip:198.51.100.45");

        MockHttpServletRequest noCfHeaderReq = new MockHttpServletRequest();
        noCfHeaderReq.setRemoteAddr("[2400:cb00::1]");
        noCfHeaderReq.addHeader("X-Forwarded-For", "198.51.100.46");
        assertThat(ClientIpResolver.extractClientIpKey(noCfHeaderReq, List.of(), cfProxies))
                .isEqualTo("ip:198.51.100.46");
    }

    @Test
    void extractClientIpKey_WalksMultiHopXForwardedForRightToLeftAndMatchesExplicitCidrs() {
        // Right-to-left multi-hop X-Forwarded-For walking across multi-tier proxies, trailing blanks, and spoofed hops
        MockHttpServletRequest twoTierProxy = new MockHttpServletRequest();
        twoTierProxy.setRemoteAddr("10.0.2.4"); // K8s Ingress
        twoTierProxy.addHeader("X-Forwarded-For", "spoofed.by.client, 198.51.100.55");
        twoTierProxy.addHeader("X-Forwarded-For", "10.0.1.9,   "); // ALB + trailing blank
        twoTierProxy.addHeader("X-Forwarded-For", "   "); // trailing blank header
        assertThat(ClientIpResolver.extractClientIpKey(twoTierProxy, List.of(), List.of()))
                .isEqualTo("ip:198.51.100.55");

        // Malformed hop stops walking immediately and returns lastTrustedHop (never trusting entries further left!)
        MockHttpServletRequest malformedMiddleHop = new MockHttpServletRequest();
        malformedMiddleHop.setRemoteAddr("10.0.2.4");
        malformedMiddleHop.addHeader("X-Forwarded-For", "203.0.113.1, bogus-hop, 10.0.1.9");
        assertThat(ClientIpResolver.extractClientIpKey(malformedMiddleHop, List.of(), List.of()))
                .isEqualTo("ip:10.0.1.9");

        // Malformed rightmost hop with no trusted hop yet falls back to peerAddr
        MockHttpServletRequest malformedRightmostHop = new MockHttpServletRequest();
        malformedRightmostHop.setRemoteAddr("10.0.2.4");
        malformedRightmostHop.addHeader("X-Forwarded-For", "203.0.113.1, bogus-hop");
        assertThat(ClientIpResolver.extractClientIpKey(malformedRightmostHop, List.of(), List.of()))
                .isEqualTo("ip:10.0.2.4");

        // All-trusted XFF chain returns leftmost trusted hop
        MockHttpServletRequest allTrustedHops = new MockHttpServletRequest();
        allTrustedHops.setRemoteAddr("10.0.2.4");
        allTrustedHops.addHeader("X-Forwarded-For", "10.0.1.1, 10.0.1.2");
        assertThat(ClientIpResolver.extractClientIpKey(allTrustedHops, List.of(), List.of()))
                .isEqualTo("ip:10.0.1.1");

        // Explicit trusted-proxies CIDR list (including non-byte-aligned /12, /25, /57, and mapped IPv4 CIDRs)
        List<IpAddressMatcher> explicitProxies = ClientIpResolver.parseTrustedProxies(
                "172.16.0.0/12, 198.51.100.128/25, 2001:db8:abcd:ef80::/57, ::ffff:192.0.2.0/120, 203.0.113.250");
        MockHttpServletRequest untrustedPrivate = new MockHttpServletRequest();
        untrustedPrivate.setRemoteAddr("10.0.0.2");
        untrustedPrivate.addHeader("X-Forwarded-For", "203.0.113.9");
        assertThat(extractClientIpKey(untrustedPrivate, explicitProxies))
                .isEqualTo("ip:10.0.0.2");

        MockHttpServletRequest matchingSlash12 = new MockHttpServletRequest();
        matchingSlash12.setRemoteAddr("172.31.255.254");
        matchingSlash12.addHeader("X-Forwarded-For", "203.0.113.9");
        assertThat(extractClientIpKey(matchingSlash12, explicitProxies))
                .isEqualTo("ip:203.0.113.9");

        MockHttpServletRequest outsideSlash12 = new MockHttpServletRequest();
        outsideSlash12.setRemoteAddr("172.32.0.1");
        outsideSlash12.addHeader("X-Forwarded-For", "203.0.113.9");
        assertThat(extractClientIpKey(outsideSlash12, explicitProxies))
                .isEqualTo("ip:172.32.0.1");

        MockHttpServletRequest matchingSlash25 = new MockHttpServletRequest();
        matchingSlash25.setRemoteAddr("198.51.100.129");
        matchingSlash25.addHeader("X-Forwarded-For", "203.0.113.10");
        assertThat(extractClientIpKey(matchingSlash25, explicitProxies))
                .isEqualTo("ip:203.0.113.10");

        MockHttpServletRequest outsideSlash25Low = new MockHttpServletRequest();
        outsideSlash25Low.setRemoteAddr("198.51.100.127");
        outsideSlash25Low.addHeader("X-Forwarded-For", "203.0.113.10");
        assertThat(extractClientIpKey(outsideSlash25Low, explicitProxies))
                .isEqualTo("ip:198.51.100.127");

        MockHttpServletRequest matchingSlash57V6 = new MockHttpServletRequest();
        matchingSlash57V6.setRemoteAddr("2001:db8:abcd:efff::9");
        matchingSlash57V6.addHeader("X-Forwarded-For", "2001:0db8:0001:0002:aaaa:bbbb:cccc:0001");
        assertThat(extractClientIpKey(matchingSlash57V6, explicitProxies))
                .isEqualTo("ip:2001:db8:1:2:0:0:0:0/64");

        assertThat(ClientIpResolver.matchesAny(null, explicitProxies)).isFalse();
        assertThat(ClientIpResolver.matchesAny(ClientIpResolver.parseIpLiteral("10.0.0.1"), null)).isFalse();
        assertThat(ClientIpResolver.matchesAny(ClientIpResolver.parseIpLiteral("10.0.0.1"), List.of())).isFalse();
        assertThat(ClientIpResolver.isTrustedProxyPeer(null, explicitProxies)).isFalse();
    }

    @Test
    void parseIpLiteralPortSplittingAndTrustedProxyValidation_RejectMalformedInputsWithoutDns() {
        MockHttpServletRequest hostnamePeer = new MockHttpServletRequest();
        hostnamePeer.setRemoteAddr("nonexistent-host.invalid");
        assertThat(extractClientIpKey(hostnamePeer, List.of()))
                .isEqualTo("ip:nonexistent-host.invalid");

        assertThat(ClientIpResolver.parseIpLiteral(null)).isNull();
        assertThat(ClientIpResolver.parseIpLiteral("   ")).isNull();
        assertThat(ClientIpResolver.parseIpLiteral("010.0.0.1")).isNull();
        assertThat(ClientIpResolver.parseIpLiteral("127.1")).isNull();
        assertThat(ClientIpResolver.parseIpLiteral("192.168.1.abc")).isNull();
        assertThat(ClientIpResolver.parseIpLiteral("256.0.0.1")).isNull();
        assertThat(ClientIpResolver.parseIpLiteral("2001:db8:::1")).isNull();
        assertThat(ClientIpResolver.parseIpLiteral("[2001:db8::1]")).isNotNull();
        assertThat(ClientIpResolver.parseIpLiteral("%en0")).isNull();
        assertThat(ClientIpResolver.parseIpLiteral("127.0.0.1%:1")).isNull();
        assertThat(ClientIpResolver.parseIpLiteral("fe80::1%")).isNull();
        assertThat(ClientIpResolver.parseIpLiteral("[127.0.0.1]")).isNull();

        assertThat(ClientIpResolver.splitHostFromRemoteAddr("")).isEmpty();
        assertThat(ClientIpResolver.splitHostFromRemoteAddr("[2001:db8::1]")).isEqualTo("2001:db8::1");
        assertThat(ClientIpResolver.splitHostFromRemoteAddr("[]")).isEqualTo("[]");
        assertThat(ClientIpResolver.splitHostFromRemoteAddr("[2001:db8::1]:")).isEqualTo("[2001:db8::1]:");
        assertThat(ClientIpResolver.splitHostFromRemoteAddr("[2001:db8::1]:abc")).isEqualTo("[2001:db8::1]:abc");
        assertThat(ClientIpResolver.splitHostFromRemoteAddr("[2001:db8::1]:70000")).isEqualTo("[2001:db8::1]:70000");
        assertThat(ClientIpResolver.splitHostFromRemoteAddr("198.51.100.1:0")).isEqualTo("198.51.100.1:0");

        assertThat(ClientIpResolver.parseTrustedProxies("")).isEmpty();
        assertThat(ClientIpResolver.parseTrustedProxies("10.0.0.0/8, , ")).hasSize(1);

        assertThatThrownBy(() -> ClientIpResolver.parseTrustedProxies("not-an-ip"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ClientIpResolver.parseTrustedProxies("not-an-ip/24"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ClientIpResolver.parseTrustedProxies("10.0.0.0/-1"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ClientIpResolver.parseTrustedProxies("10.0.0.0/33"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ClientIpResolver.parseTrustedProxies("10.0.0.0/abc"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ClientIpResolver.parseTrustedProxies("10.0.0.0/8/16"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
