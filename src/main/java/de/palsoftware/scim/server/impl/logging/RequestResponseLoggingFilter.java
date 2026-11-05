package de.palsoftware.scim.server.impl.logging;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import de.palsoftware.scim.server.impl.model.ScimRequestLog;
import de.palsoftware.scim.server.impl.repository.ScimRequestLogRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
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
import java.util.Map;
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
    private static final Pattern WORKSPACE_PATH = Pattern.compile("/ws/([0-9a-fA-F-]+)/scim/v2/.*");
    private static final int MAX_BODY_CHARS = 20000;

    // Regex fallbacks for malformed or truncated JSON payloads containing passwords
    private static final Pattern MALFORMED_PASSWORD_KV = Pattern.compile(
            "(?is)(\"(?:[^\"\\\\]*:)?password\"\\s*:\\s*)(?:\"(?:\\\\.|[^\"\\\\])*\"|\"(?:\\\\.|[^\"\\\\])*$)");
    private static final Pattern MALFORMED_PATCH_PATH_FIRST = Pattern.compile(
            "(?is)(\"path\"\\s*:\\s*\"(?:[^\"\\\\]*:)?password\"[^{}]*?,\\s*\"value\"\\s*:\\s*)(?:\"(?:\\\\.|[^\"\\\\])*\"|\"(?:\\\\.|[^\"\\\\])*$)");
    private static final Pattern MALFORMED_PATCH_VALUE_FIRST = Pattern.compile(
            "(?is)(\"value\"\\s*:\\s*)\"(?:\\\\.|[^\"\\\\])*\"([^{}]*?,\\s*\"path\"\\s*:\\s*\"(?:[^\"\\\\]*:)?password(?:\"|$))");

    private final ScimRequestLogRepository logRepository;
    private final WorkspaceRepository workspaceRepository;

    public RequestResponseLoggingFilter(ScimRequestLogRepository logRepository,
            WorkspaceRepository workspaceRepository) {
        this.logRepository = logRepository;
        this.workspaceRepository = workspaceRepository;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/ws/") || !path.contains("/scim/v2/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(request, MAX_BODY_CHARS);
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(response);

        try {
            filterChain.doFilter(requestWrapper, responseWrapper);
        } finally {
            try {
                saveLog(requestWrapper, responseWrapper);
            } finally {
                responseWrapper.copyBodyToResponse();
            }
        }
    }

    private void saveLog(ContentCachingRequestWrapper request, ContentCachingResponseWrapper response) {
        UUID workspaceId = extractWorkspaceId(request.getRequestURI());
        if (workspaceId == null) {
            return;
        }

        ScimRequestLog log = new ScimRequestLog();
        log.setWorkspace(workspaceRepository.getReferenceById(workspaceId));
        log.setMethod(request.getMethod());
        log.setPath(request.getRequestURI());
        log.setStatus(response.getStatus());
        log.setRequestBody(truncate(redactPasswords(readBody(request.getContentAsByteArray(), request.getCharacterEncoding()))));
        log.setResponseBody(truncate(redactPasswords(readBody(response.getContentAsByteArray(), response.getCharacterEncoding()))));
        logRepository.save(log);
    }

    static String redactPasswords(String body) {
        if (body == null || body.isEmpty()) {
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
                if (isPasswordAttributeOrPath(key)) {
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

    private static String redactWithRegexFallback(String body) {
        String redacted = MALFORMED_PASSWORD_KV.matcher(body).replaceAll("$1\"[REDACTED]\"");
        redacted = MALFORMED_PATCH_PATH_FIRST.matcher(redacted).replaceAll("$1\"[REDACTED]\"");
        redacted = MALFORMED_PATCH_VALUE_FIRST.matcher(redacted).replaceAll("$1\"[REDACTED]\"$2");
        return redacted;
    }

    private UUID extractWorkspaceId(String path) {
        Matcher matcher = WORKSPACE_PATH.matcher(path);
        if (!matcher.matches()) {
            return null;
        }
        String workspaceId = matcher.group(1);
        try {
            return UUID.fromString(workspaceId);
        } catch (IllegalArgumentException _) {
            return null;
        }
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
