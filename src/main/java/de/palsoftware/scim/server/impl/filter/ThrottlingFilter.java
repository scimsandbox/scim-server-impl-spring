package de.palsoftware.scim.server.impl.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.util.concurrent.RateLimiter;
import de.palsoftware.scim.server.impl.metrics.ScimRequestMetricAttributes;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Component
@ConditionalOnProperty(prefix = "app.rate-limit", name = "enabled", havingValue = "true", matchIfMissing = false)
public class ThrottlingFilter extends OncePerRequestFilter {

    static final Duration DEFAULT_WAIT_TIMEOUT = Duration.ZERO;
    static final String RETRY_AFTER_SECONDS = "1";
    static final String CAPACITY_ERROR_DETAIL = "Too many requests. Try again later.";

    private final PermitLimiter permitLimiter;
    private final Duration waitTimeout;
    private final ObjectMapper objectMapper;

    @Autowired
    public ThrottlingFilter(@Value("${app.rate-limit.requests-per-second}") double requestsPerSecond,
                            @Value("${app.rate-limit.wait-timeout:0s}") Duration waitTimeout,
                            ObjectMapper objectMapper) {
        this(new GuavaPermitLimiter(RateLimiter.create(requestsPerSecond)), waitTimeout, objectMapper);
    }

    public ThrottlingFilter(PermitLimiter permitLimiter, Duration waitTimeout, ObjectMapper objectMapper) {
        this.permitLimiter = permitLimiter;
        this.waitTimeout = resolveWaitTimeout(waitTimeout);
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri != null && ("/actuator".equals(uri) || uri.startsWith("/actuator/"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        request.setAttribute(ScimRequestMetricAttributes.THROTTLED, ScimRequestMetricAttributes.THROTTLED_NO);

        if (!permitLimiter.tryAcquire(waitTimeout)) {
            request.setAttribute(ScimRequestMetricAttributes.THROTTLED, ScimRequestMetricAttributes.THROTTLED_YES);
            sendScimRateLimitError(response);
            return;
        }

        chain.doFilter(request, response);
    }

    private static Duration resolveWaitTimeout(Duration configuredWaitTimeout) {
        if (configuredWaitTimeout == null || configuredWaitTimeout.isNegative()) {
            return DEFAULT_WAIT_TIMEOUT;
        }
        return configuredWaitTimeout;
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

    public interface PermitLimiter {
        boolean tryAcquire(Duration timeout);
    }

    private static final class GuavaPermitLimiter implements PermitLimiter {

        private final RateLimiter rateLimiter;

        private GuavaPermitLimiter(RateLimiter rateLimiter) {
            this.rateLimiter = rateLimiter;
        }

        @Override
        public boolean tryAcquire(Duration timeout) {
            if (timeout.isZero()) {
                return rateLimiter.tryAcquire(1);
            }
            return rateLimiter.tryAcquire(1, timeout.toNanos(), TimeUnit.NANOSECONDS);
        }
    }
}
