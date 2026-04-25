package de.palsoftware.scim.server.impl.metrics;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.method.HandlerMethod;
import de.palsoftware.scim.server.impl.controller.ScimUserController;
import de.palsoftware.scim.server.impl.controller.ScimGroupController;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ScimOperationMetricsInterceptorTest {

    private MeterRegistry meterRegistry;
    private ScimOperationMetricsInterceptor interceptor;

    @BeforeEach
    void setUp() {
        meterRegistry = new SimpleMeterRegistry();
        interceptor = new ScimOperationMetricsInterceptor(meterRegistry);
    }

    @Test
    void shouldRecordMetrics() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/api/scim/v2/Users");
        request.setMethod("POST");
        request.setAttribute("WORKSPACE_ID", "ws-123");
        request.setAttribute("USER_EMAIL", "test@example.com");

        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setStatus(201);

        // use a real controller to pass the package name check
        Method[] methods = ScimUserController.class.getDeclaredMethods();
        Method method = null;
        for (Method m : methods) {
            if (m.getName().equals("createUser")) {
                method = m;
                break;
            }
        }
        HandlerMethod handlerMethod = new HandlerMethod(new ScimUserController(null), method);

        interceptor.preHandle(request, response, handlerMethod);
        interceptor.afterCompletion(request, response, handlerMethod, null);

        assertEquals(1, meterRegistry.counter("scim.operation.requests", 
                "operation", method.getName(), 
                "resource", "users", 
                "action", "create", 
                "workspace_id", "ws-123", 
                "user_email", "test@example.com", 
                "http_status", "201", 
                "outcome", "success").count());

        assertNotNull(meterRegistry.timer("scim.operation.duration", 
                "operation", method.getName(), 
                "resource", "users", 
                "action", "create", 
                "workspace_id", "ws-123", 
                "user_email", "test@example.com", 
                "http_status", "201", 
                "outcome", "success"));
    }

    @Test
    void shouldRecordErrorMetrics() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/api/scim/v2/Groups/123");
        request.setMethod("GET");

        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setStatus(404);

        Method[] methods = ScimGroupController.class.getDeclaredMethods();
        Method method = null;
        for (Method m : methods) {
            if (m.getName().equals("getGroup")) {
                method = m;
                break;
            }
        }
        HandlerMethod handlerMethod = new HandlerMethod(new ScimGroupController(null), method);

        interceptor.preHandle(request, response, handlerMethod);
        interceptor.afterCompletion(request, response, handlerMethod, new RuntimeException("Not found"));

        assertEquals(1, meterRegistry.counter("scim.operation.requests", 
                "operation", method.getName(), 
                "resource", "groups", 
                "action", "get", 
                "workspace_id", "unknown", 
                "user_email", "unknown", 
                "http_status", "404", 
                "outcome", "server_error").count());
    }
}
