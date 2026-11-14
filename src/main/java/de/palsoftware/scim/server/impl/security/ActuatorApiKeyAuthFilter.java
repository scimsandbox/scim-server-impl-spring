package de.palsoftware.scim.server.impl.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.scim.error.ScimFilterErrorWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * Authenticates Spring Boot Actuator endpoints using a constant-time SHA-256 comparison
 * against {@code X-API-Key} or {@code Authorization: Bearer <key>}.
 * <ul>
 *   <li>{@code /actuator/health} and {@code /actuator/health/**} are always permitted;
 *       supplying a valid API key (or accessing via the dedicated management port when no key
 *       is configured) populates an authenticated principal so {@code show-components: when_authorized}
 *       is honored without exposing component details publicly.</li>
 *   <li>Other {@code /actuator/**} endpoints require a valid API key when
 *       {@code app.security.actuator.api-key} is non-blank (returning 401 otherwise).</li>
 *   <li>When {@code app.security.actuator.api-key} is blank, other {@code /actuator/**} endpoints
 *       are permitted ONLY on the dedicated management port ({@code request.getLocalPort() == managementPort})
 *       and denied on the main SCIM port.</li>
 * </ul>
 */
public class ActuatorApiKeyAuthFilter extends OncePerRequestFilter {

    public static final String HEADER_API_KEY = "X-API-Key";
    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String ROLE_ACTUATOR = "ROLE_ACTUATOR";

    private final byte[] expectedKeyDigest;
    private final int configuredManagementPort;
    private final int configuredServerPort;
    private final ObjectMapper objectMapper;

    private volatile int runtimeManagementPort = -1;
    private volatile int runtimeServerPort = -1;

    public ActuatorApiKeyAuthFilter(String configuredApiKey,
                                    int configuredManagementPort,
                                    int configuredServerPort,
                                    ObjectMapper objectMapper) {
        this.expectedKeyDigest = StringUtils.hasText(configuredApiKey)
                ? sha256Bytes(configuredApiKey.trim())
                : null;
        this.configuredManagementPort = configuredManagementPort;
        this.configuredServerPort = configuredServerPort;
        this.objectMapper = objectMapper;
    }

    public void updateRuntimePort(String serverNamespace, int port) {
        if (port <= 0) {
            return;
        }
        if ("management".equals(serverNamespace)) {
            this.runtimeManagementPort = port;
        } else if (!StringUtils.hasText(serverNamespace)) {
            this.runtimeServerPort = port;
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !RequestPaths.isActuatorPath(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String uri = request.getRequestURI();
        if (isHealthEndpoint(uri)) {
            if (isAuthorizedForActuator(request)) {
                authenticateActuatorContext();
            }
            filterChain.doFilter(request, response);
            return;
        }

        if (expectedKeyDigest != null) {
            if (!hasMatchingApiKey(request)) {
                ScimFilterErrorWriter.writeScimError(
                        response,
                        objectMapper,
                        HttpServletResponse.SC_UNAUTHORIZED,
                        null,
                        "Missing or invalid actuator API key");
                return;
            }
            authenticateActuatorContext();
            filterChain.doFilter(request, response);
            return;
        }

        if (isDedicatedManagementPortRequest(request)) {
            authenticateActuatorContext();
            filterChain.doFilter(request, response);
            return;
        }

        ScimFilterErrorWriter.writeScimError(
                response,
                objectMapper,
                HttpServletResponse.SC_FORBIDDEN,
                null,
                "Actuator endpoint is restricted to the management port");
    }

    private boolean isAuthorizedForActuator(HttpServletRequest request) {
        if (expectedKeyDigest != null) {
            return hasMatchingApiKey(request);
        }
        return isDedicatedManagementPortRequest(request);
    }

    private boolean hasMatchingApiKey(HttpServletRequest request) {
        if (expectedKeyDigest == null) {
            return false;
        }
        String xApiKey = request.getHeader(HEADER_API_KEY);
        if (StringUtils.hasText(xApiKey) && matchesExpectedDigest(xApiKey.trim())) {
            return true;
        }
        String authHeader = request.getHeader(HEADER_AUTHORIZATION);
        if (authHeader != null && authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            String bearer = authHeader.substring(7).trim();
            return StringUtils.hasText(bearer) && matchesExpectedDigest(bearer);
        }
        return false;
    }

    private boolean matchesExpectedDigest(String candidate) {
        byte[] candidateDigest = sha256Bytes(candidate);
        return MessageDigest.isEqual(expectedKeyDigest, candidateDigest);
    }

    private boolean isDedicatedManagementPortRequest(HttpServletRequest request) {
        int effectiveMgmtPort = runtimeManagementPort > 0 ? runtimeManagementPort : configuredManagementPort;
        if (effectiveMgmtPort <= 0) {
            return false;
        }
        int effectiveMainPort = runtimeServerPort > 0 ? runtimeServerPort : configuredServerPort;
        if (effectiveMainPort > 0 && effectiveMgmtPort == effectiveMainPort) {
            return false;
        }
        return request.getLocalPort() == effectiveMgmtPort;
    }

    private static boolean isHealthEndpoint(String uri) {
        return "/actuator/health".equals(uri) || uri.startsWith("/actuator/health/");
    }

    private static void authenticateActuatorContext() {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(new UsernamePasswordAuthenticationToken(
                "actuator",
                null,
                List.of(new SimpleGrantedAuthority(ROLE_ACTUATOR))));
        SecurityContextHolder.setContext(context);
    }

    private static byte[] sha256Bytes(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
