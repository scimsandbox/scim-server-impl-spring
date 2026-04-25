package de.palsoftware.scim.server.impl.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class ActuatorApiKeyAuthFilter extends OncePerRequestFilter {

    public static final String API_KEY_HEADER = "X-API-KEY";

    private final String actuatorApiKey;

    public ActuatorApiKeyAuthFilter(String actuatorApiKey) {
        if (actuatorApiKey == null || actuatorApiKey.isBlank()) {
            throw new IllegalArgumentException("Actuator API key must be configured");
        }
        this.actuatorApiKey = actuatorApiKey;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/actuator/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String providedApiKey = request.getHeader(API_KEY_HEADER);
        if (providedApiKey == null || !MessageDigest.isEqual(
                actuatorApiKey.getBytes(StandardCharsets.UTF_8),
                providedApiKey.getBytes(StandardCharsets.UTF_8))) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing or invalid actuator API key");
            return;
        }

        filterChain.doFilter(request, response);
    }
}