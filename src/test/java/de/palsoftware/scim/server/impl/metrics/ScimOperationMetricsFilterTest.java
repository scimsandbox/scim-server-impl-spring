package de.palsoftware.scim.server.impl.metrics;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
                "resource", "users",
                "action", "create",
                "workspace_id", workspaceId.toString(),
                "user_email", "test@example.com",
                "http_status", "201",
                "outcome", "success",
                "authentication", "ok",
                "throttled", "no").count());

        assertNotNull(meterRegistry.timer("scim.operation.duration",
                "operation", "createUser",
                "resource", "users",
                "action", "create",
                "workspace_id", workspaceId.toString(),
                "user_email", "test@example.com",
                "http_status", "201",
                "outcome", "success",
                "authentication", "ok",
                "throttled", "no"));
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
                "resource", "groups",
                "action", "get",
                "workspace_id", workspaceId.toString(),
                "user_email", "unknown",
                "http_status", "401",
                "outcome", "client_error",
                "authentication", "failed",
                "throttled", "no").count());
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
                "resource", "bulk",
                "action", "process",
                "workspace_id", workspaceId.toString(),
                "user_email", "test@example.com",
                "http_status", "503",
                "outcome", "server_error",
                "authentication", "ok",
                "throttled", "yes").count());
    }
}