package de.palsoftware.scim.server.impl.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.util.concurrent.RateLimiter;
import de.palsoftware.scim.server.impl.metrics.ScimRequestMetricAttributes;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Component
@ConditionalOnProperty(prefix = "app.rate-limit", name = "enabled", havingValue = "true", matchIfMissing = false)
public class ThrottlingFilter extends org.springframework.web.filter.GenericFilterBean {

    static final Duration DEFAULT_WAIT_TIMEOUT = Duration.ofSeconds(60);
    static final String RETRY_AFTER_SECONDS = "300";
    static final String CAPACITY_ERROR_DETAIL = "The server reached max capacity. Try again later.";

    private final PermitLimiter permitLimiter;
    private final Duration waitTimeout;
    private final ObjectMapper objectMapper;

    @Autowired
    public ThrottlingFilter(@Value("${app.rate-limit.requests-per-second}") double requestsPerSecond,
                            @Value("${app.rate-limit.wait-timeout:60s}") Duration waitTimeout,
                            ObjectMapper objectMapper) {
        this(new GuavaPermitLimiter(RateLimiter.create(requestsPerSecond)), waitTimeout, objectMapper);
    }

    ThrottlingFilter(PermitLimiter permitLimiter, Duration waitTimeout, ObjectMapper objectMapper) {
        this.permitLimiter = permitLimiter;
        this.waitTimeout = resolveWaitTimeout(waitTimeout);
        this.objectMapper = objectMapper;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        request.setAttribute(ScimRequestMetricAttributes.THROTTLED, ScimRequestMetricAttributes.THROTTLED_NO);

        if (!permitLimiter.tryAcquire(waitTimeout)) {
            request.setAttribute(ScimRequestMetricAttributes.THROTTLED, ScimRequestMetricAttributes.THROTTLED_YES);
            sendScimCapacityError(httpResponse);
            return;
        }

        chain.doFilter(request, response);
    }

    private Duration resolveWaitTimeout(Duration configuredWaitTimeout) {
        if (configuredWaitTimeout == null || configuredWaitTimeout.isZero()) {
            return DEFAULT_WAIT_TIMEOUT;
        }

        return configuredWaitTimeout;
    }

    private void sendScimCapacityError(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        response.setHeader("Retry-After", RETRY_AFTER_SECONDS);
        response.setContentType("application/scim+json;charset=UTF-8");

        Map<String, Object> error = new LinkedHashMap<>();
        error.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:Error"));
        error.put("status", String.valueOf(HttpServletResponse.SC_SERVICE_UNAVAILABLE));
        error.put("detail", CAPACITY_ERROR_DETAIL);

        response.getWriter().write(objectMapper.writeValueAsString(error));
    }

    interface PermitLimiter {
        boolean tryAcquire(Duration timeout);
    }

    private static final class GuavaPermitLimiter implements PermitLimiter {

        private final RateLimiter rateLimiter;

        private GuavaPermitLimiter(RateLimiter rateLimiter) {
            this.rateLimiter = rateLimiter;
        }

        @Override
        public boolean tryAcquire(Duration timeout) {
            return rateLimiter.tryAcquire(1, timeout.toNanos(), TimeUnit.NANOSECONDS);
        }
    }
}
