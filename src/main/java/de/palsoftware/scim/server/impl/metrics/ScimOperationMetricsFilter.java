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
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

@Component
public class ScimOperationMetricsFilter extends OncePerRequestFilter {

    private static final Set<String> TRACKED_RESOURCES = Set.of("Users", "Groups", "Bulk");

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
        String workspaceId = resolveWorkspaceId(request);
        String userEmail = resolveUserEmail(request);
        String authentication = resolveAuthentication(request, httpStatus);
        String throttled = resolveThrottled(request, response, httpStatus);
        String outcome = resolveOutcome(failure, httpStatus);

        List<Tag> tags = new ArrayList<>();
        tags.add(Tag.of("operation", scimOperation.operation()));
        tags.add(Tag.of("resource", scimOperation.resource()));
        tags.add(Tag.of("action", scimOperation.action()));
        tags.add(Tag.of("workspace_id", workspaceId));
        tags.add(Tag.of("user_email", userEmail));
        tags.add(Tag.of("http_status", Integer.toString(httpStatus)));
        tags.add(Tag.of("outcome", outcome));
        tags.add(Tag.of("authentication", authentication));
        tags.add(Tag.of("throttled", throttled));

        meterRegistry.counter("scim.operation.requests", tags).increment();
        sample.stop(Timer.builder("scim.operation.duration")
                .description("Duration of SCIM API operations")
                .publishPercentileHistogram()
                .tags(tags)
                .register(meterRegistry));
    }

    private int resolveHttpStatus(int responseStatus, Exception failure) {
        if (failure != null && responseStatus < HttpServletResponse.SC_BAD_REQUEST) {
            return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }

        return responseStatus;
    }

    private String resolveWorkspaceId(HttpServletRequest request) {
        String workspaceId = attributeValue(request, "WORKSPACE_ID");
        if (StringUtils.hasText(workspaceId)) {
            return workspaceId;
        }

        String[] segments = request.getRequestURI().split("/");
        if (segments.length <= 2 || !"ws".equals(segments[1])) {
            return "unknown";
        }

        try {
            return UUID.fromString(segments[2]).toString();
        } catch (IllegalArgumentException ex) {
            return "invalid";
        }
    }

    private String resolveUserEmail(HttpServletRequest request) {
        String userEmail = attributeValue(request, "USER_EMAIL");
        if (StringUtils.hasText(userEmail)) {
            return userEmail;
        }

        return "unknown";
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

    private String resolveOutcome(Exception ex, int status) {
        if (ex != null || status >= 500) {
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

    private record ScimOperation(String operation, String resource, String action) {

        private static ScimOperation unknown() {
            return new ScimOperation("unknown", "unknown", "unknown");
        }
    }
}