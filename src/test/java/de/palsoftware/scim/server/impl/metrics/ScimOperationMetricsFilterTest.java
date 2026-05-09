package de.palsoftware.scim.server.impl.metrics;

import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScimOperationMetricsFilterTest {

    private MeterRegistry meterRegistry;
    private ScimOperationMetricsFilter filter;

    @BeforeEach
    void setUp() {
        meterRegistry = new SimpleMeterRegistry();
        filter = new ScimOperationMetricsFilter(meterRegistry);
    }

    @Test
    void shouldRecordMetricsForSuccessfulRequest() throws Exception {
        UUID workspaceId = UUID.randomUUID();
        MockHttpServletRequest request = new MockHttpServletRequest("POST",
                "/ws/" + workspaceId + "/scim/v2/Users");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = Mockito.mock(FilterChain.class);

        Mockito.doAnswer(invocation -> {
            MockHttpServletRequest currentRequest = (MockHttpServletRequest) invocation.getArgument(0);
            MockHttpServletResponse currentResponse = (MockHttpServletResponse) invocation.getArgument(1);
            currentRequest.setAttribute("WORKSPACE_ID", workspaceId.toString());
            currentRequest.setAttribute("USER_EMAIL", "test@example.com");
            currentRequest.setAttribute(ScimRequestMetricAttributes.AUTHENTICATION, ScimRequestMetricAttributes.AUTH_OK);
            currentRequest.setAttribute(ScimRequestMetricAttributes.THROTTLED, ScimRequestMetricAttributes.THROTTLED_NO);
            currentResponse.setStatus(201);
            return null;
        }).when(filterChain).doFilter(Mockito.any(), Mockito.any());

        filter.doFilter(request, response, filterChain);

        assertEquals(1, meterRegistry.counter("scim.operation.requests",
                "operation", "createUser",
            "http_status", "201").count());

        assertNotNull(meterRegistry.timer("scim.operation.duration",
                "operation", "createUser",
            "http_status", "201"));

        assertEquals(1, meterRegistry.counter("scim.operation.authentication",
            "state", "ok").count());
        assertEquals(1, meterRegistry.counter("scim.operation.throttled",
            "state", "no").count());
    }

    @Test
    void shouldRecordAuthFailureMetrics() throws Exception {
        UUID workspaceId = UUID.randomUUID();
        MockHttpServletRequest request = new MockHttpServletRequest("GET",
                "/ws/" + workspaceId + "/scim/v2/Groups/123");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = Mockito.mock(FilterChain.class);

        Mockito.doAnswer(invocation -> {
            MockHttpServletRequest currentRequest = (MockHttpServletRequest) invocation.getArgument(0);
            MockHttpServletResponse currentResponse = (MockHttpServletResponse) invocation.getArgument(1);
            currentRequest.setAttribute(ScimRequestMetricAttributes.AUTHENTICATION, ScimRequestMetricAttributes.AUTH_FAILED);
            currentResponse.setStatus(401);
            return null;
        }).when(filterChain).doFilter(Mockito.any(), Mockito.any());

        filter.doFilter(request, response, filterChain);

        assertEquals(1, meterRegistry.counter("scim.operation.requests",
                "operation", "getGroup",
            "http_status", "401").count());
        assertEquals(1, meterRegistry.counter("scim.operation.authentication",
            "state", "failed").count());
        assertEquals(1, meterRegistry.counter("scim.operation.throttled",
            "state", "no").count());
    }

    @Test
    void shouldRecordThrottledMetrics() throws Exception {
        UUID workspaceId = UUID.randomUUID();
        MockHttpServletRequest request = new MockHttpServletRequest("POST",
                "/ws/" + workspaceId + "/scim/v2/Bulk");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = Mockito.mock(FilterChain.class);

        Mockito.doAnswer(invocation -> {
            MockHttpServletRequest currentRequest = (MockHttpServletRequest) invocation.getArgument(0);
            MockHttpServletResponse currentResponse = (MockHttpServletResponse) invocation.getArgument(1);
            currentRequest.setAttribute("WORKSPACE_ID", workspaceId.toString());
            currentRequest.setAttribute("USER_EMAIL", "test@example.com");
            currentRequest.setAttribute(ScimRequestMetricAttributes.AUTHENTICATION, ScimRequestMetricAttributes.AUTH_OK);
            currentRequest.setAttribute(ScimRequestMetricAttributes.THROTTLED, ScimRequestMetricAttributes.THROTTLED_YES);
            currentResponse.setStatus(503);
            currentResponse.setHeader("Retry-After", "300");
            return null;
        }).when(filterChain).doFilter(Mockito.any(), Mockito.any());

        filter.doFilter(request, response, filterChain);

        assertEquals(1, meterRegistry.counter("scim.operation.requests",
                "operation", "processBulk",
            "http_status", "503").count());
        assertEquals(1, meterRegistry.counter("scim.operation.authentication",
            "state", "ok").count());
        assertEquals(1, meterRegistry.counter("scim.operation.throttled",
            "state", "yes").count());
        }

    @Test
    void shouldExposePrometheusTimerWithConfiguredBuckets() throws Exception {
        PrometheusMeterRegistry prometheusRegistry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        ScimOperationMetricsFilter prometheusFilter = new ScimOperationMetricsFilter(prometheusRegistry);

        UUID workspaceId = UUID.randomUUID();
        MockHttpServletRequest request = new MockHttpServletRequest("POST",
            "/ws/" + workspaceId + "/scim/v2/Users");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = Mockito.mock(FilterChain.class);

        Mockito.doAnswer(invocation -> {
            MockHttpServletRequest currentRequest = (MockHttpServletRequest) invocation.getArgument(0);
            MockHttpServletResponse currentResponse = (MockHttpServletResponse) invocation.getArgument(1);
            currentRequest.setAttribute(ScimRequestMetricAttributes.AUTHENTICATION, ScimRequestMetricAttributes.AUTH_OK);
            currentRequest.setAttribute(ScimRequestMetricAttributes.THROTTLED, ScimRequestMetricAttributes.THROTTLED_NO);
            currentResponse.setStatus(201);
            return null;
        }).when(filterChain).doFilter(Mockito.any(), Mockito.any());

        prometheusFilter.doFilter(request, response, filterChain);

        String scrape = prometheusRegistry.scrape();
        assertTrue(containsMetricLine(scrape, "scim_operation_duration_seconds_count",
            "operation=\"createUser\"", "http_status=\"201\""));
        assertTrue(containsMetricLine(scrape, "scim_operation_duration_seconds_sum",
            "operation=\"createUser\"", "http_status=\"201\""));
        assertTrue(containsMetricLine(scrape, "scim_operation_duration_seconds_bucket",
            "operation=\"createUser\"", "http_status=\"201\"", "le=\"0.05\""));
        assertTrue(containsMetricLine(scrape, "scim_operation_duration_seconds_bucket",
            "operation=\"createUser\"", "http_status=\"201\"", "le=\"0.1\""));
        assertTrue(containsMetricLine(scrape, "scim_operation_duration_seconds_bucket",
            "operation=\"createUser\"", "http_status=\"201\"", "le=\"0.25\""));
        assertTrue(containsMetricLine(scrape, "scim_operation_duration_seconds_bucket",
            "operation=\"createUser\"", "http_status=\"201\"", "le=\"0.5\""));
        assertTrue(containsMetricLine(scrape, "scim_operation_duration_seconds_bucket",
            "operation=\"createUser\"", "http_status=\"201\"", "le=\"1.0\""));
        assertTrue(containsMetricLine(scrape, "scim_operation_duration_seconds_bucket",
            "operation=\"createUser\"", "http_status=\"201\"", "le=\"+Inf\""));
        assertFalse(scrape.contains("scim_operation_duration_seconds_bucket{http_status=\"201\",operation=\"createUser\",le=\"0.075\"}"));
        }

        private boolean containsMetricLine(String scrape, String metricName, String... substrings) {
        for (String line : scrape.split("\\R")) {
            if (!line.startsWith(metricName + "{")) {
            continue;
            }

            boolean matches = true;
            for (String substring : substrings) {
            if (!line.contains(substring)) {
                matches = false;
                break;
            }
            }
            if (matches) {
            return true;
            }
        }

        return false;
    }
}