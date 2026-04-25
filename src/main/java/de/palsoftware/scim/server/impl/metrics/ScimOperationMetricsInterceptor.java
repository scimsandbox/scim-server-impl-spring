package de.palsoftware.scim.server.impl.metrics;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Timer;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.List;
import java.util.Locale;
import java.util.Set;

@Component
public class ScimOperationMetricsInterceptor implements HandlerInterceptor {

    private static final Set<String> TRACKED_RESOURCES = Set.of("Users", "Groups", "Bulk");

    private static final String ATTR_OPERATION = ScimOperationMetricsInterceptor.class.getName() + ".operation";
    private static final String ATTR_SAMPLE = ScimOperationMetricsInterceptor.class.getName() + ".sample";

    private final MeterRegistry meterRegistry;

    public ScimOperationMetricsInterceptor(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        ScimOperation operation = resolveOperation(request.getRequestURI(), request.getMethod());
        if (operation != null) {
            request.setAttribute(ATTR_OPERATION, operation);
            request.setAttribute(ATTR_SAMPLE, Timer.start(meterRegistry));
        }
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request,
            HttpServletResponse response,
            Object handler,
            Exception ex) {
        ScimOperation operation = (ScimOperation) request.getAttribute(ATTR_OPERATION);
        Timer.Sample sample = (Timer.Sample) request.getAttribute(ATTR_SAMPLE);
        if (operation == null || sample == null) {
            return;
        }

        String status = Integer.toString(response.getStatus());
        String outcome = resolveOutcome(response.getStatus());
        List<Tag> tags = List.of(
                Tag.of("resource", operation.resource()),
                Tag.of("action", operation.action()),
                Tag.of("status", status),
                Tag.of("outcome", outcome));

        meterRegistry.counter("scim.operation.requests", tags).increment();
        sample.stop(Timer.builder("scim.operation.duration")
                .description("Duration of SCIM user, group, and bulk operations.")
                .publishPercentileHistogram()
                .tags(tags)
                .register(meterRegistry));
    }

    private ScimOperation resolveOperation(String requestUri, String method) {
        String[] segments = requestUri.split("/");
        if (segments.length < 6
                || !"ws".equals(segments[1])
                || !"scim".equals(segments[3])
                || !"v2".equals(segments[4])) {
            return null;
        }

        int resourceIndex = 5;
        if (segments.length > resourceIndex && !isTrackedResource(segments[resourceIndex])) {
            resourceIndex++;
        }
        if (segments.length <= resourceIndex || !isTrackedResource(segments[resourceIndex])) {
            return null;
        }

        String resource = segments[resourceIndex].toLowerCase(Locale.ROOT);
        if ("bulk".equals(resource)) {
            return resolveBulkOperation(segments, resourceIndex, resource, method);
        }

        boolean hasResourceId = segments.length > resourceIndex + 1 && !segments[resourceIndex + 1].isBlank();
        String action = switch (method) {
            case "POST" -> hasResourceId ? null : "create";
            case "GET" -> hasResourceId ? "get" : "list";
            case "PUT" -> hasResourceId ? "replace" : null;
            case "PATCH" -> hasResourceId ? "patch" : null;
            case "DELETE" -> hasResourceId ? "delete" : null;
            default -> null;
        };
        if (action == null) {
            return null;
        }

        return new ScimOperation(resource, action);
    }

    private ScimOperation resolveBulkOperation(String[] segments, int resourceIndex, String resource, String method) {
        boolean bulkCollectionRequest = segments.length == resourceIndex + 1
                || (segments.length == resourceIndex + 2 && segments[resourceIndex + 1].isBlank());
        if (!bulkCollectionRequest || !"POST".equals(method)) {
            return null;
        }
        return new ScimOperation(resource, "process");
    }

    private boolean isTrackedResource(String segment) {
        return TRACKED_RESOURCES.contains(segment);
    }

    private String resolveOutcome(int status) {
        if (status >= 500) {
            return "server_error";
        }
        if (status >= 400) {
            return "client_error";
        }
        if (status >= 300) {
            return "redirection";
        }
        if (status >= 200) {
            return "success";
        }
        return "unknown";
    }

    private record ScimOperation(String resource, String action) {
    }
}