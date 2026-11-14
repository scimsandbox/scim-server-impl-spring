package de.palsoftware.scim.server.impl.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.metrics.ScimRequestMetricAttributes;
import de.palsoftware.scim.server.impl.scim.error.ScimFilterErrorWriter;
import de.palsoftware.scim.server.impl.security.BearerTokenAuthFilter;
import de.palsoftware.scim.server.impl.security.RequestPaths;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Objects;
import java.util.UUID;

/**
 * Tier 3 post-authentication per-workspace SCIM rate-limiting filter.
 * <p>
 * Runs strictly AFTER {@link BearerTokenAuthFilter} and consumes permits ONLY when
 * {@link BearerTokenAuthFilter#AUTHENTICATED_WORKSPACE_ID} has been verified, preventing
 * unauthenticated or invalid-token callers from draining a tenant's workspace bucket.
 */
@Component
@ConditionalOnProperty(prefix = "app.rate-limit", name = "enabled", havingValue = "true", matchIfMissing = false)
public class WorkspaceRateLimitFilter extends OncePerRequestFilter {

    private final ThrottlingFilter.KeyedPermitLimiter permitLimiter;
    private final Duration waitTimeout;
    private final ObjectMapper objectMapper;

    @Autowired
    public WorkspaceRateLimitFilter(
            @Value("${app.rate-limit.requests-per-second}") double globalRequestsPerSecond,
            @Value("${app.rate-limit.burst:0}") int globalBurst,
            @Value("${app.rate-limit.per-workspace-requests-per-second:0}") double perWorkspaceRequestsPerSecond,
            @Value("${app.rate-limit.per-workspace-burst:0}") int perWorkspaceBurst,
            @Value("${app.rate-limit.wait-timeout:0s}") Duration waitTimeout,
            ObjectMapper objectMapper) {
        this(createDefaultWorkspaceLimiter(
                globalRequestsPerSecond, globalBurst, perWorkspaceRequestsPerSecond, perWorkspaceBurst),
                waitTimeout,
                objectMapper);
    }

    public WorkspaceRateLimitFilter(ThrottlingFilter.KeyedPermitLimiter permitLimiter,
                                    Duration waitTimeout,
                                    ObjectMapper objectMapper) {
        this.permitLimiter = Objects.requireNonNull(permitLimiter, "permitLimiter must not be null");
        this.waitTimeout = ThrottlingFilter.resolveWaitTimeout(waitTimeout);
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    }

    private static ThrottlingFilter.KeyedPermitLimiter createDefaultWorkspaceLimiter(
            double globalRequestsPerSecond,
            int globalBurst,
            double perWorkspaceRequestsPerSecond,
            int perWorkspaceBurst) {
        ThrottlingFilter.SubRateLimit wsLimit = ThrottlingFilter.resolveSubRateLimit(
                globalRequestsPerSecond, globalBurst, perWorkspaceRequestsPerSecond, perWorkspaceBurst);
        return ThrottlingFilter.createKeyedLimiter(wsLimit.requestsPerSecond(), wsLimit.burst());
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return RequestPaths.isActuatorPath(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Object attr = request.getAttribute(BearerTokenAuthFilter.AUTHENTICATED_WORKSPACE_ID);
        if (!(attr instanceof UUID workspaceId)) {
            filterChain.doFilter(request, response);
            return;
        }

        request.setAttribute(ScimRequestMetricAttributes.THROTTLED, ScimRequestMetricAttributes.THROTTLED_NO);
        ThrottlingFilter.AcquireResult result = permitLimiter.tryAcquire("ws:" + workspaceId, waitTimeout);
        if (!result.allowed()) {
            request.setAttribute(ScimRequestMetricAttributes.THROTTLED, ScimRequestMetricAttributes.THROTTLED_YES);
            ScimFilterErrorWriter.writeScimError(
                    response,
                    objectMapper,
                    HttpStatus.TOO_MANY_REQUESTS.value(),
                    null,
                    ThrottlingFilter.CAPACITY_ERROR_DETAIL,
                    "Retry-After",
                    Long.toString(Math.max(1L, result.retryAfterSeconds())));
            return;
        }

        filterChain.doFilter(request, response);
    }
}
