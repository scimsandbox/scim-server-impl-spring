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
    void availablePermit_PassesThroughAndDefaultsWaitTimeoutTo60Seconds() throws Exception {
        AtomicReference<Duration> observedTimeout = new AtomicReference<>();
        ThrottlingFilter filter = new ThrottlingFilter(timeout -> {
            observedTimeout.set(timeout);
            return true;
        }, Duration.ZERO, new ObjectMapper());

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(Duration.ofSeconds(60), observedTimeout.get());
        assertEquals(ScimRequestMetricAttributes.THROTTLED_NO,
            request.getAttribute(ScimRequestMetricAttributes.THROTTLED));
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void timedOutPermitWait_ReturnsScim503WithRetryAfter() throws Exception {
        ThrottlingFilter filter = new ThrottlingFilter(timeout -> false, Duration.ofSeconds(5), new ObjectMapper());

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(503, response.getStatus());
        assertEquals("300", response.getHeader("Retry-After"));
        assertEquals("application/scim+json;charset=UTF-8", response.getContentType());
        assertEquals(ScimRequestMetricAttributes.THROTTLED_YES,
            request.getAttribute(ScimRequestMetricAttributes.THROTTLED));

        String body = response.getContentAsString();
        assertTrue(body.contains("urn:ietf:params:scim:api:messages:2.0:Error"));
        assertTrue(body.contains("\"status\":\"503\""));
        assertTrue(body.contains("The server reached max capacity. Try again later."));

        verifyNoInteractions(filterChain);
    }
}