package de.palsoftware.scim.server.impl.logging;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import de.palsoftware.scim.server.impl.controller.ScimBulkController;
import de.palsoftware.scim.server.impl.model.ScimRequestLog;
import de.palsoftware.scim.server.impl.repository.ScimRequestLogRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
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

    // Linear-time possessive regex fallbacks for malformed or truncated JSON payloads containing passwords
    private static final Pattern MALFORMED_PASSWORD_KV = Pattern.compile(
            "(?is)(\"(?:[^\"\\\\]*:)?password\"\\s*+:\\s*+)(?:\"(?:\\\\.|[^\"\\\\])*+\"|\"(?:\\\\.|[^\"\\\\])*+$)");
    private static final Pattern FLAT_OBJECT_SEGMENT = Pattern.compile("\\{[^{}]*+(?:\\}|$)");
    private static final Pattern SEGMENT_HAS_PASSWORD_PATH = Pattern.compile(
            "(?is)\"path\"\\s*+:\\s*+\"(?:[^\"\\\\]*:)?password(?:[.\\[][^\"\\\\]*+)?(?:\"|$)");
    private static final Pattern SEGMENT_VALUE_FIELD = Pattern.compile(
            "(?is)(\"value\"\\s*+:\\s*+)(?:\"(?:\\\\.|[^\"\\\\])*+\"|\"(?:\\\\.|[^\"\\\\])*+$)");

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
            if (isBulkPostRequest(request)) {
                if (request.getContentLengthLong() > ScimBulkController.MAX_PAYLOAD_SIZE) {
                    writeScimErrorResponse(responseWrapper, 413, null,
                            "Bulk request payload size exceeds maxPayloadSize of " + ScimBulkController.MAX_PAYLOAD_SIZE + " bytes");
                    return;
                }
                HttpServletRequest boundedRequest = new BoundedBulkRequestWrapper(
                        requestWrapper, ScimBulkController.MAX_PAYLOAD_SIZE);
                try {
                    filterChain.doFilter(boundedRequest, responseWrapper);
                } catch (Exception ex) {
                    ScimException payloadEx = findScimExceptionByStatus(ex, 413);
                    if (payloadEx != null && !responseWrapper.isCommitted()) {
                        responseWrapper.resetBuffer();
                        writeScimErrorResponse(responseWrapper, 413, payloadEx.getScimType(), payloadEx.getMessage());
                        return;
                    }
                    throw ex;
                }
            } else {
                filterChain.doFilter(requestWrapper, responseWrapper);
            }
        } finally {
            try {
                saveLog(requestWrapper, responseWrapper);
            } finally {
                responseWrapper.copyBodyToResponse();
            }
        }
    }

    private static boolean isBulkPostRequest(HttpServletRequest request) {
        if (request == null || !"POST".equalsIgnoreCase(request.getMethod())) {
            return false;
        }
        String uri = request.getRequestURI();
        return uri != null && (uri.endsWith("/Bulk") || uri.endsWith("/Bulk/"));
    }

    private static ScimException findScimExceptionByStatus(Throwable ex, int status) {
        Throwable cur = ex;
        while (cur != null) {
            if (cur instanceof ScimException scimEx && scimEx.getHttpStatus() == status) {
                return scimEx;
            }
            cur = cur.getCause() != cur ? cur.getCause() : null;
        }
        return null;
    }

    private static void writeScimErrorResponse(HttpServletResponse response, int status, String scimType, String detail)
            throws IOException {
        response.setStatus(status);
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/scim+json;charset=UTF-8");
        Map<String, Object> error = new LinkedHashMap<>();
        error.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:Error"));
        error.put("status", String.valueOf(status));
        if (scimType != null) {
            error.put("scimType", scimType);
        }
        error.put("detail", detail);
        response.getWriter().write(OBJECT_MAPPER.writeValueAsString(error));
        response.getWriter().flush();
    }

    private static final class BoundedBulkRequestWrapper extends HttpServletRequestWrapper {
        private final int maxBytes;
        private ServletInputStream boundedInputStream;
        private BufferedReader boundedReader;

        BoundedBulkRequestWrapper(HttpServletRequest request, int maxBytes) {
            super(request);
            this.maxBytes = maxBytes;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (boundedInputStream == null) {
                ServletInputStream delegate = super.getInputStream();
                boundedInputStream = new ServletInputStream() {
                    private long bytesRead = 0;

                    private void addBytes(int count) {
                        if (count > 0) {
                            bytesRead += count;
                            if (bytesRead > maxBytes) {
                                throw new ScimException(413, null,
                                        "Bulk request payload size exceeds maxPayloadSize of " + maxBytes + " bytes");
                            }
                        }
                    }

                    @Override
                    public int read() throws IOException {
                        int b = delegate.read();
                        if (b != -1) {
                            addBytes(1);
                        }
                        return b;
                    }

                    @Override
                    public int read(byte[] b, int off, int len) throws IOException {
                        int n = delegate.read(b, off, len);
                        addBytes(n);
                        return n;
                    }

                    @Override
                    public boolean isFinished() {
                        return delegate.isFinished();
                    }

                    @Override
                    public boolean isReady() {
                        return delegate.isReady();
                    }

                    @Override
                    public void setReadListener(ReadListener readListener) {
                        delegate.setReadListener(readListener);
                    }

                    @Override
                    public void close() throws IOException {
                        delegate.close();
                    }
                };
            }
            return boundedInputStream;
        }

        @Override
        public BufferedReader getReader() throws IOException {
            if (boundedReader == null) {
                String enc = getCharacterEncoding();
                Charset cs = StringUtils.hasText(enc) ? Charset.forName(enc) : StandardCharsets.UTF_8;
                boundedReader = new BufferedReader(new InputStreamReader(getInputStream(), cs));
            }
            return boundedReader;
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
        if (body == null || body.isEmpty() || !containsPasswordIgnoreCase(body)) {
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

    private static boolean containsPasswordIgnoreCase(String rawBody) {
        if (rawBody == null) {
            return false;
        }
        int limit = rawBody.length() - 8;
        for (int i = 0; i <= limit; i++) {
            char c = rawBody.charAt(i);
            if ((c == 'p' || c == 'P') && rawBody.regionMatches(true, i, "password", 0, 8)) {
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

    static String redactWithRegexFallback(String rawBody) {
        if (rawBody == null || rawBody.isEmpty() || !containsPasswordIgnoreCase(rawBody)) {
            return rawBody;
        }
        String step1 = MALFORMED_PASSWORD_KV.matcher(rawBody).replaceAll("$1\"[REDACTED]\"");
        Matcher segMatcher = FLAT_OBJECT_SEGMENT.matcher(step1);
        StringBuilder sb = new StringBuilder(step1.length());
        while (segMatcher.find()) {
            String seg = segMatcher.group();
            if (containsPasswordIgnoreCase(seg) && SEGMENT_HAS_PASSWORD_PATH.matcher(seg).find()) {
                seg = SEGMENT_VALUE_FIELD.matcher(seg).replaceAll("$1\"[REDACTED]\"");
            }
            segMatcher.appendReplacement(sb, Matcher.quoteReplacement(seg));
        }
        segMatcher.appendTail(sb);
        return sb.toString();
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
