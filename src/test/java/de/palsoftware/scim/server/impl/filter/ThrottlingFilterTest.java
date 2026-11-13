package de.palsoftware.scim.server.impl.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.metrics.ScimRequestMetricAttributes;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class ThrottlingFilterTest {

    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        filterChain = Mockito.mock(FilterChain.class);
    }

    @Test
    void availablePermit_PassesThroughAndDefaultsWaitTimeoutToZeroFailFast() throws Exception {
        AtomicReference<Duration> observedTimeout = new AtomicReference<>();
        ThrottlingFilter filter = new ThrottlingFilter(timeout -> {
            observedTimeout.set(timeout);
            return true;
        }, null, new ObjectMapper());

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/ws/123/scim/v2/Users");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(Duration.ZERO, observedTimeout.get());
        assertEquals(ScimRequestMetricAttributes.THROTTLED_NO,
            request.getAttribute(ScimRequestMetricAttributes.THROTTLED));
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void exhaustedPermit_FailsFastWithScim429AndRetryAfterOneSecond() throws Exception {
        ThrottlingFilter filter = new ThrottlingFilter(timeout -> false, Duration.ZERO, new ObjectMapper());

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/ws/123/scim/v2/Users");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(429, response.getStatus());
        assertEquals("1", response.getHeader("Retry-After"));
        assertEquals("application/scim+json;charset=UTF-8", response.getContentType());
        assertEquals(ScimRequestMetricAttributes.THROTTLED_YES,
            request.getAttribute(ScimRequestMetricAttributes.THROTTLED));

        String body = response.getContentAsString();
        assertTrue(body.contains("urn:ietf:params:scim:api:messages:2.0:Error"));
        assertTrue(body.contains("\"status\":\"429\""));
        assertTrue(body.contains("Too many requests. Try again later."));

        verifyNoInteractions(filterChain);
    }

    @Test
    void actuatorEndpoints_SkipThrottlingWithoutConsumingPermits() throws Exception {
        java.util.concurrent.atomic.AtomicInteger permitsAcquired = new java.util.concurrent.atomic.AtomicInteger();
        ThrottlingFilter filter = new ThrottlingFilter(timeout -> {
            permitsAcquired.incrementAndGet();
            return false;
        }, Duration.ZERO, new ObjectMapper());

        for (String actuatorPath : java.util.List.of("/actuator", "/actuator/health", "/actuator/health/liveness", "/actuator/prometheus")) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", actuatorPath);
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, filterChain);
            assertEquals(200, response.getStatus());
        }

        assertEquals(0, permitsAcquired.get());
        verify(filterChain, Mockito.times(4)).doFilter(Mockito.any(), Mockito.any());
    }
}