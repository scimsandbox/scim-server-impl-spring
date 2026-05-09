package de.palsoftware.scim.server.impl.metrics;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Timer;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Component
public class ScimOperationMetricsFilter extends OncePerRequestFilter {

    private static final Set<String> TRACKED_RESOURCES = Set.of("Users", "Groups", "Bulk");
    private static final Duration[] SCIM_DURATION_SLOS = {
            Duration.ofMillis(50),
            Duration.ofMillis(100),
            Duration.ofMillis(250),
            Duration.ofMillis(500),
            Duration.ofSeconds(1)
    };

    private final MeterRegistry meterRegistry;

    public ScimOperationMetricsFilter(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path == null || !path.startsWith("/ws/") || !path.contains("/scim/v2");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        Timer.Sample sample = Timer.start(meterRegistry);
        Exception failure = null;

        try {
            filterChain.doFilter(request, response);
        } catch (ServletException | IOException | RuntimeException ex) {
            failure = ex;
            throw ex;
        } finally {
            recordMetrics(request, response, sample, failure);
        }
    }

    private void recordMetrics(HttpServletRequest request,
            HttpServletResponse response,
            Timer.Sample sample,
            Exception failure) {
        ScimOperation scimOperation = resolveOperation(request.getRequestURI(), request.getMethod());
        if (scimOperation == null) {
            scimOperation = ScimOperation.unknown();
        }

        int httpStatus = resolveHttpStatus(response.getStatus(), failure);
        String authentication = resolveAuthentication(request, httpStatus);
        String throttled = resolveThrottled(request, response, httpStatus);

        List<Tag> operationTags = new ArrayList<>();
        operationTags.add(Tag.of("operation", scimOperation.operation()));
        operationTags.add(Tag.of("http_status", Integer.toString(httpStatus)));

        meterRegistry.counter("scim.operation.requests", operationTags).increment();
        sample.stop(Timer.builder("scim.operation.duration")
                .description("Duration of SCIM API operations")
                .serviceLevelObjectives(SCIM_DURATION_SLOS)
                .tags(operationTags)
                .register(meterRegistry));
        meterRegistry.counter("scim.operation.authentication", "state", authentication).increment();
        meterRegistry.counter("scim.operation.throttled", "state", throttled).increment();
    }

    private int resolveHttpStatus(int responseStatus, Exception failure) {
        if (failure != null && responseStatus < HttpServletResponse.SC_BAD_REQUEST) {
            return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }

        return responseStatus;
    }

    private String resolveAuthentication(HttpServletRequest request, int httpStatus) {
        String authentication = attributeValue(request, ScimRequestMetricAttributes.AUTHENTICATION);
        if (StringUtils.hasText(authentication)) {
            return authentication;
        }

        if (StringUtils.hasText(attributeValue(request, "WORKSPACE_ID"))
                || StringUtils.hasText(attributeValue(request, "USER_EMAIL"))) {
            return ScimRequestMetricAttributes.AUTH_OK;
        }

        if (httpStatus == HttpServletResponse.SC_UNAUTHORIZED || httpStatus == HttpServletResponse.SC_FORBIDDEN) {
            return ScimRequestMetricAttributes.AUTH_FAILED;
        }

        return ScimRequestMetricAttributes.AUTH_UNKNOWN;
    }

    private String resolveThrottled(HttpServletRequest request, HttpServletResponse response, int httpStatus) {
        String throttled = attributeValue(request, ScimRequestMetricAttributes.THROTTLED);
        if (StringUtils.hasText(throttled)) {
            return throttled;
        }

        if (httpStatus == HttpServletResponse.SC_SERVICE_UNAVAILABLE
                && StringUtils.hasText(response.getHeader("Retry-After"))) {
            return ScimRequestMetricAttributes.THROTTLED_YES;
        }

        return ScimRequestMetricAttributes.THROTTLED_NO;
    }

    private String attributeValue(HttpServletRequest request, String attributeName) {
        Object value = request.getAttribute(attributeName);
        return value instanceof String text ? text : null;
    }

    private ScimOperation resolveOperation(String requestUri, String method) {
        if (requestUri == null) {
            return null;
        }

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

        return new ScimOperation(resolveOperationName(resource, action), resource, action);
    }

    private ScimOperation resolveBulkOperation(String[] segments, int resourceIndex, String resource, String method) {
        boolean bulkCollectionRequest = segments.length == resourceIndex + 1
                || (segments.length == resourceIndex + 2 && segments[resourceIndex + 1].isBlank());
        if (!bulkCollectionRequest || !"POST".equals(method)) {
            return null;
        }
        return new ScimOperation("processBulk", resource, "process");
    }

    private boolean isTrackedResource(String segment) {
        return TRACKED_RESOURCES.contains(segment);
    }

    private String resolveOperationName(String resource, String action) {
        return switch (resource) {
            case "users" -> switch (action) {
                case "create" -> "createUser";
                case "list" -> "listUsers";
                case "get" -> "getUser";
                case "replace" -> "replaceUser";
                case "patch" -> "patchUser";
                case "delete" -> "deleteUser";
                default -> "unknown";
            };
            case "groups" -> switch (action) {
                case "create" -> "createGroup";
                case "list" -> "listGroups";
                case "get" -> "getGroup";
                case "replace" -> "replaceGroup";
                case "patch" -> "patchGroup";
                case "delete" -> "deleteGroup";
                default -> "unknown";
            };
            case "bulk" -> "processBulk";
            default -> "unknown";
        };
    }

    private record ScimOperation(String operation, String resource, String action) {

        private static ScimOperation unknown() {
            return new ScimOperation("unknown", "unknown", "unknown");
        }
    }
}