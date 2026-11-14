package de.palsoftware.scim.server.impl.logging;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import de.palsoftware.scim.server.impl.model.ScimRequestLog;
import de.palsoftware.scim.server.impl.repository.ScimRequestLogRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.security.RequestPaths;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

@Component
public class RequestResponseLoggingFilter extends OncePerRequestFilter {

    private static final String REDACTED = "[REDACTED]";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final int MAX_BODY_CHARS = 20000;

    // Linear-time possessive regex fallbacks for malformed or truncated JSON payloads containing passwords or auth tokens
    private static final Pattern MALFORMED_SENSITIVE_KV = Pattern.compile(
            "(?is)(\"(?:[^\"\\\\]*:)?(?:password|authorization)\"\\s*+:\\s*+)(?:\"(?:\\\\.|[^\"\\\\])*+\"|(?:\"(?:\\\\.|[^\"\\\\])*+$))");
    private static final Pattern FLAT_OBJECT_SEGMENT = Pattern.compile("\\{[^{}]*+(?:\\}|$)");
    private static final Pattern SEGMENT_HAS_PASSWORD_PATH = Pattern.compile(
            "(?is)\"path\"\\s*+:\\s*+\"(?:[^\"\\\\]*:)?password(?:[.\\[][^\"\\\\]*+)?(?:\"|$)");
    private static final Pattern SEGMENT_VALUE_FIELD = Pattern.compile(
            "(?is)(\"value\"\\s*+:\\s*+)(?:\"(?:\\\\.|[^\"\\\\])*+\"|(?:\"(?:\\\\.|[^\"\\\\])*+$))");

    private final ScimRequestLogRepository logRepository;
    private final WorkspaceRepository workspaceRepository;

    public RequestResponseLoggingFilter(ScimRequestLogRepository logRepository,
            WorkspaceRepository workspaceRepository) {
        this.logRepository = logRepository;
        this.workspaceRepository = workspaceRepository;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !RequestPaths.isScimPath(request);
    }

    @Override
    @SuppressWarnings("java:S1181") // Rethrows Error immediately after recording failure status in finally
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(request, MAX_BODY_CHARS);
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(response);
        Throwable failure = null;

        try {
            filterChain.doFilter(requestWrapper, responseWrapper);
        } catch (ServletException | IOException | RuntimeException | Error ex) {
            failure = ex;
            throw ex;
        } finally {
            try {
                saveLog(requestWrapper, responseWrapper, failure);
            } finally {
                responseWrapper.copyBodyToResponse();
            }
        }
    }

    private void saveLog(ContentCachingRequestWrapper request,
                         ContentCachingResponseWrapper response,
                         Throwable failure) {
        UUID workspaceId = RequestPaths.extractWorkspaceId(request.getRequestURI());
        if (workspaceId == null) {
            return;
        }

        ScimRequestLog log = new ScimRequestLog();
        log.setWorkspace(workspaceRepository.getReferenceById(workspaceId));
        log.setMethod(request.getMethod());
        log.setPath(request.getRequestURI());
        log.setStatus(resolveStatus(response.getStatus(), failure));
        log.setRequestBody(truncate(redactPasswords(readBody(request.getContentAsByteArray(), request.getCharacterEncoding()))));
        log.setResponseBody(truncate(redactPasswords(readBody(response.getContentAsByteArray(), response.getCharacterEncoding()))));
        logRepository.save(log);
    }

    private static int resolveStatus(int responseStatus, Throwable failure) {
        if (failure != null && responseStatus < HttpServletResponse.SC_BAD_REQUEST) {
            Throwable cur = failure;
            while (cur != null) {
                if (cur instanceof ScimException scimEx) {
                    return scimEx.getHttpStatus();
                }
                cur = cur.getCause() != cur ? cur.getCause() : null;
            }
            return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }
        return responseStatus;
    }

    static String redactPasswords(String body) {
        if (body == null || body.isEmpty() || !containsSensitiveTokenIgnoreCase(body)) {
            return body;
        }
        try {
            JsonNode root = OBJECT_MAPPER.readTree(body);
            if (root != null && (root.isObject() || root.isArray())) {
                if (redactJsonNode(root)) {
                    return OBJECT_MAPPER.writeValueAsString(root);
                }
                return body;
            }
        } catch (Exception _) {
            // Fall through to regex redaction for malformed or truncated JSON
        }
        return redactWithRegexFallback(body);
    }

    private static boolean containsSensitiveTokenIgnoreCase(String rawBody) {
        return containsKeywordIgnoreCase(rawBody, "password")
                || containsKeywordIgnoreCase(rawBody, "authorization");
    }

    private static boolean containsKeywordIgnoreCase(String rawBody, String keyword) {
        if (rawBody == null) {
            return false;
        }
        int kwLen = keyword.length();
        int limit = rawBody.length() - kwLen;
        char firstLower = Character.toLowerCase(keyword.charAt(0));
        char firstUpper = Character.toUpperCase(keyword.charAt(0));
        for (int i = 0; i <= limit; i++) {
            char c = rawBody.charAt(i);
            if ((c == firstLower || c == firstUpper) && rawBody.regionMatches(true, i, keyword, 0, kwLen)) {
                return true;
            }
        }
        return false;
    }

    private static boolean redactJsonNode(JsonNode node) {
        if (node == null) {
            return false;
        }
        boolean modified = false;
        if (node instanceof ObjectNode obj) {
            boolean patchTargetsPassword = false;
            List<String> keys = new ArrayList<>();
            Iterator<String> fieldNames = obj.fieldNames();
            while (fieldNames.hasNext()) {
                String key = fieldNames.next();
                keys.add(key);
                if ("path".equalsIgnoreCase(key)) {
                    JsonNode pathVal = obj.get(key);
                    if (pathVal != null && pathVal.isTextual() && isPasswordAttributeOrPath(pathVal.asText())) {
                        patchTargetsPassword = true;
                    }
                }
            }
            for (String key : keys) {
                JsonNode child = obj.get(key);
                if (isSensitiveAttributeOrPath(key)) {
                    if (child != null && !child.isNull()) {
                        obj.set(key, TextNode.valueOf(REDACTED));
                        modified = true;
                    }
                } else if (patchTargetsPassword && "value".equalsIgnoreCase(key)) {
                    if (child != null && !child.isNull()) {
                        obj.set(key, TextNode.valueOf(REDACTED));
                        modified = true;
                    }
                } else if (child != null && (child.isObject() || child.isArray())) {
                    if (redactJsonNode(child)) {
                        modified = true;
                    }
                }
            }
        } else if (node instanceof ArrayNode arr) {
            for (int i = 0; i < arr.size(); i++) {
                if (redactJsonNode(arr.get(i))) {
                    modified = true;
                }
            }
        }
        return modified;
    }

    private static boolean isSensitiveAttributeOrPath(String raw) {
        if (isPasswordAttributeOrPath(raw)) {
            return true;
        }
        if (raw == null || raw.isBlank()) {
            return false;
        }
        String lower = raw.trim().toLowerCase(Locale.ROOT);
        return "authorization".equals(lower) || lower.endsWith(":authorization");
    }

    private static boolean isPasswordAttributeOrPath(String raw) {
        if (raw == null || raw.isBlank()) {
            return false;
        }
        String lower = raw.trim().toLowerCase(Locale.ROOT);
        return "password".equals(lower)
                || lower.endsWith(":password")
                || lower.startsWith("password.")
                || lower.startsWith("password[")
                || lower.contains(":password.")
                || lower.contains(":password[");
    }

    static String redactWithRegexFallback(String rawBody) {
        if (rawBody == null || rawBody.isEmpty() || !containsSensitiveTokenIgnoreCase(rawBody)) {
            return rawBody;
        }
        String step1 = MALFORMED_SENSITIVE_KV.matcher(rawBody).replaceAll("$1\"[REDACTED]\"");
        Matcher segMatcher = FLAT_OBJECT_SEGMENT.matcher(step1);
        StringBuilder sb = new StringBuilder(step1.length());
        while (segMatcher.find()) {
            String seg = segMatcher.group();
            if (containsKeywordIgnoreCase(seg, "password") && SEGMENT_HAS_PASSWORD_PATH.matcher(seg).find()) {
                seg = SEGMENT_VALUE_FIELD.matcher(seg).replaceAll("$1\"[REDACTED]\"");
            }
            segMatcher.appendReplacement(sb, Matcher.quoteReplacement(seg));
        }
        segMatcher.appendTail(sb);
        return sb.toString();
    }

    private String readBody(byte[] body, String encoding) {
        if (body == null || body.length == 0) {
            return null;
        }
        Charset charset = StringUtils.hasText(encoding) ? Charset.forName(encoding) : StandardCharsets.UTF_8;
        return new String(body, charset);
    }

    private String truncate(String body) {
        if (body == null) {
            return null;
        }
        if (body.length() <= MAX_BODY_CHARS) {
            return body;
        }
        return body.substring(0, MAX_BODY_CHARS) + "...";
    }
}
