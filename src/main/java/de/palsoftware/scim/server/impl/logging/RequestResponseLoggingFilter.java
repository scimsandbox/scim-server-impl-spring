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
import de.palsoftware.scim.server.impl.scim.error.ScimFilterErrorWriter;
import de.palsoftware.scim.server.impl.security.RequestPaths;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Component
public class RequestResponseLoggingFilter extends OncePerRequestFilter {

    private static final String REDACTED = "[REDACTED]";
    private static final String QUOTED_REDACTED = "\"[REDACTED]\"";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final int MAX_BODY_CHARS = 20000;
    private static final int MAX_DECODED_TOKEN_LEN = 512;

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
            ScimException scimEx = ScimFilterErrorWriter.findScimException(failure);
            if (scimEx != null) {
                return scimEx.getHttpStatus();
            }
            return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }
        return responseStatus;
    }

    static String redactPasswords(String body) {
        if (body == null || body.isEmpty()) {
            return body;
        }
        boolean directSensitive = hasDirectSensitiveToken(body);
        if (!directSensitive && !mayHaveTruncatedPatchValue(body)) {
            return body;
        }
        try {
            JsonNode root = OBJECT_MAPPER.readTree(body);
            if (root != null && (root.isObject() || root.isArray())) {
                if (directSensitive && redactJsonNode(root)) {
                    return OBJECT_MAPPER.writeValueAsString(root);
                }
                return body;
            }
        } catch (Exception _) {
            // Fall through to deterministic O(n) character scanner for malformed or truncated JSON
        }
        return redactMalformedJsonFallback(body);
    }

    private static boolean hasDirectSensitiveToken(String rawBody) {
        return containsKeywordIgnoreCase(rawBody, "password")
                || containsKeywordIgnoreCase(rawBody, "authorization")
                || rawBody.indexOf("\\u") >= 0
                || rawBody.indexOf("\\U") >= 0;
    }

    private static boolean mayHaveTruncatedPatchValue(String rawBody) {
        return containsKeywordIgnoreCase(rawBody, "value")
                && (containsKeywordIgnoreCase(rawBody, "path")
                || containsKeywordIgnoreCase(rawBody, "op")
                || containsKeywordIgnoreCase(rawBody, "operations"));
    }

    private static boolean containsKeywordIgnoreCase(String rawBody, String keyword) {
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
        if (node instanceof ObjectNode obj) {
            return redactObjectNode(obj);
        }
        if (node instanceof ArrayNode arr) {
            return redactArrayNode(arr);
        }
        return false;
    }

    private static boolean redactObjectNode(ObjectNode obj) {
        boolean patchTargetsSensitive = hasSensitivePatchPath(obj);
        List<String> keys = new ArrayList<>();
        Iterator<String> fieldNames = obj.fieldNames();
        while (fieldNames.hasNext()) {
            keys.add(fieldNames.next());
        }

        boolean modified = false;
        for (String key : keys) {
            JsonNode child = obj.get(key);
            if (child == null || child.isNull()) {
                continue;
            }
            if (isSensitiveAttributeOrPath(key) || (patchTargetsSensitive && "value".equalsIgnoreCase(key))) {
                obj.set(key, TextNode.valueOf(REDACTED));
                modified = true;
            } else if ((child.isObject() || child.isArray()) && redactJsonNode(child)) {
                modified = true;
            }
        }
        return modified;
    }

    private static boolean hasSensitivePatchPath(ObjectNode obj) {
        Iterator<String> fieldNames = obj.fieldNames();
        while (fieldNames.hasNext()) {
            String key = fieldNames.next();
            if ("path".equalsIgnoreCase(key)) {
                JsonNode pathVal = obj.get(key);
                if (pathVal != null && pathVal.isTextual() && isSensitiveAttributeOrPath(pathVal.asText())) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean redactArrayNode(ArrayNode arr) {
        boolean modified = false;
        for (int i = 0; i < arr.size(); i++) {
            if (redactJsonNode(arr.get(i))) {
                modified = true;
            }
        }
        return modified;
    }

    static boolean isSensitiveAttributeOrPath(String raw) {
        if (raw == null || raw.isBlank()) {
            return false;
        }
        String lower = raw.trim().toLowerCase(Locale.ROOT);
        return matchesAttributeOrPath(lower, "password")
                || matchesAttributeOrPath(lower, "authorization");
    }

    private static boolean matchesAttributeOrPath(String lower, String attr) {
        return lower.equals(attr)
                || lower.endsWith(":" + attr)
                || lower.endsWith("." + attr)
                || lower.startsWith(attr + ".")
                || lower.startsWith(attr + "[")
                || lower.contains(":" + attr + ".")
                || lower.contains(":" + attr + "[")
                || lower.contains("." + attr + ".")
                || lower.contains("." + attr + "[");
    }

    // ── Linear-time O(n) broken/truncated JSON fallback scanner ──────────────

    static String redactMalformedJsonFallback(String rawBody) {
        if (rawBody == null || rawBody.isEmpty()
                || (!hasDirectSensitiveToken(rawBody) && !mayHaveTruncatedPatchValue(rawBody))) {
            return rawBody;
        }
        List<Span> spans = scanMalformedJson(rawBody);
        if (spans.isEmpty()) {
            return rawBody;
        }
        return applyReplacementSpans(rawBody, spans);
    }

    private enum ContainerKind {
        OBJECT,
        ARRAY
    }

    private enum KeyKind {
        NONE,
        SENSITIVE,
        PATH,
        VALUE,
        OP,
        OPERATIONS,
        OTHER
    }

    private record Span(int start, int end) {
    }

    private record StringToken(String decoded, int start, int end, boolean closed) {
    }

    private static final class ContainerFrame {
        final ContainerKind kind;
        final int valStart;
        final KeyKind boundKeyInParent;
        final boolean isOperationsArray;
        final boolean inOperationsArray;

        boolean expectingValue;
        KeyKind currentKey = KeyKind.NONE;
        boolean sawOpField;
        boolean sawSensitivePath;
        boolean sawClosedNonSensitivePath;
        List<Span> valueFieldSpans;

        private ContainerFrame(ContainerKind kind,
                               int valStart,
                               KeyKind boundKeyInParent,
                               boolean isOperationsArray,
                               boolean inOperationsArray) {
            this.kind = kind;
            this.valStart = valStart;
            this.boundKeyInParent = boundKeyInParent;
            this.isOperationsArray = isOperationsArray;
            this.inOperationsArray = inOperationsArray;
        }

        static ContainerFrame objectFrame(int valStart, KeyKind boundKeyInParent, boolean inOperationsArray) {
            return new ContainerFrame(ContainerKind.OBJECT, valStart, boundKeyInParent, false, inOperationsArray);
        }

        static ContainerFrame arrayFrame(int valStart, KeyKind boundKeyInParent, boolean isOperationsArray) {
            return new ContainerFrame(ContainerKind.ARRAY, valStart, boundKeyInParent, isOperationsArray, false);
        }

        void addValueSpan(int start, int end) {
            if (end > start) {
                if (valueFieldSpans == null) {
                    valueFieldSpans = new ArrayList<>(2);
                }
                valueFieldSpans.add(new Span(start, end));
            }
        }
    }

    private static List<Span> scanMalformedJson(String s) {
        Deque<ContainerFrame> stack = new ArrayDeque<>();
        List<Span> spans = new ArrayList<>();
        int n = s.length();
        int i = 0;

        while (i < n) {
            i = skipWhitespace(s, i);
            if (i >= n) {
                break;
            }
            ContainerFrame top = stack.peekLast();
            if (top == null) {
                i = stepTopLevel(s, i, stack);
            } else if (top.kind == ContainerKind.ARRAY) {
                i = stepArray(s, i, top, stack, spans);
            } else if (top.expectingValue) {
                i = stepObjectValue(s, i, top, stack, spans);
            } else {
                i = stepObjectKeyOrEnd(s, i, top, stack, spans);
            }
        }

        unwindUnclosedFrames(stack, n, spans);
        return spans;
    }

    private static int stepTopLevel(String s, int i, Deque<ContainerFrame> stack) {
        char c = s.charAt(i);
        if (c == '{') {
            stack.addLast(ContainerFrame.objectFrame(i, KeyKind.NONE, false));
            return i + 1;
        }
        if (c == '[') {
            stack.addLast(ContainerFrame.arrayFrame(i, KeyKind.NONE, false));
            return i + 1;
        }
        if (c == '"') {
            StringToken tok = scanQuotedString(s, i);
            int afterKey = skipWhitespace(s, tok.end());
            if (afterKey < s.length() && s.charAt(afterKey) == ':') {
                ContainerFrame synthetic = ContainerFrame.objectFrame(i, KeyKind.NONE, false);
                applyObservedKey(synthetic, classifyKey(tok.decoded()));
                synthetic.expectingValue = true;
                stack.addLast(synthetic);
                return afterKey + 1;
            }
            return tok.end();
        }
        return i + 1;
    }

    private static int stepArray(String s,
                                 int i,
                                 ContainerFrame top,
                                 Deque<ContainerFrame> stack,
                                 List<Span> spans) {
        char c = s.charAt(i);
        if (c == ']') {
            stack.removeLast();
            finishCompositeValue(stack.peekLast(), top.boundKeyInParent, top.valStart, i + 1, spans);
            return i + 1;
        }
        if (c == '{') {
            stack.addLast(ContainerFrame.objectFrame(i, KeyKind.NONE, top.isOperationsArray));
            return i + 1;
        }
        if (c == '[') {
            stack.addLast(ContainerFrame.arrayFrame(i, KeyKind.NONE, false));
            return i + 1;
        }
        if (c == '"') {
            return scanQuotedString(s, i).end();
        }
        if (c == '}' && hasEnclosingObject(stack)) {
            stack.removeLast();
            finishCompositeValue(stack.peekLast(), top.boundKeyInParent, top.valStart, i, spans);
            return i;
        }
        if (c == ',') {
            return i + 1;
        }
        return Math.max(i + 1, scanBareToken(s, i));
    }

    private static boolean hasEnclosingObject(Deque<ContainerFrame> stack) {
        for (ContainerFrame frame : stack) {
            if (frame.kind == ContainerKind.OBJECT) {
                return true;
            }
        }
        return false;
    }

    private static int stepObjectKeyOrEnd(String s,
                                          int i,
                                          ContainerFrame frame,
                                          Deque<ContainerFrame> stack,
                                          List<Span> spans) {
        char c = s.charAt(i);
        if (c == '}') {
            stack.removeLast();
            finalizeObjectFrame(frame, true, spans);
            finishCompositeValue(stack.peekLast(), frame.boundKeyInParent, frame.valStart, i + 1, spans);
            return i + 1;
        }
        if (c == '"') {
            StringToken keyTok = scanQuotedString(s, i);
            int afterKey = skipWhitespace(s, keyTok.end());
            if (afterKey < s.length() && s.charAt(afterKey) == ':') {
                applyObservedKey(frame, classifyKey(keyTok.decoded()));
                frame.expectingValue = true;
                return afterKey + 1;
            }
            return keyTok.end();
        }
        if (c == '{') {
            stack.addLast(ContainerFrame.objectFrame(i, KeyKind.NONE, false));
            return i + 1;
        }
        if (c == '[') {
            stack.addLast(ContainerFrame.arrayFrame(i, KeyKind.NONE, false));
            return i + 1;
        }
        return i + 1;
    }

    private static void applyObservedKey(ContainerFrame frame, KeyKind keyKind) {
        frame.currentKey = keyKind;
        if (keyKind == KeyKind.OP) {
            frame.sawOpField = true;
        }
    }

    private static int stepObjectValue(String s,
                                       int i,
                                       ContainerFrame frame,
                                       Deque<ContainerFrame> stack,
                                       List<Span> spans) {
        char c = s.charAt(i);
        KeyKind keyKind = frame.currentKey;
        frame.currentKey = KeyKind.NONE;
        frame.expectingValue = false;

        if (c == '"') {
            StringToken valTok = scanQuotedString(s, i);
            recordStringFieldValue(frame, keyKind, valTok, spans);
            return valTok.end();
        }
        if (c == '{') {
            stack.addLast(ContainerFrame.objectFrame(i, keyKind, false));
            return i + 1;
        }
        if (c == '[') {
            stack.addLast(ContainerFrame.arrayFrame(i, keyKind, keyKind == KeyKind.OPERATIONS));
            return i + 1;
        }
        if (c == ',' || c == '}' || c == ']') {
            return i;
        }

        int tokEnd = Math.max(i + 1, scanBareToken(s, i));
        recordBareFieldValue(frame, keyKind, i, tokEnd, s.substring(i, tokEnd), spans);
        return tokEnd;
    }

    private static void recordStringFieldValue(ContainerFrame frame,
                                               KeyKind keyKind,
                                               StringToken valTok,
                                               List<Span> spans) {
        if (keyKind == KeyKind.SENSITIVE) {
            spans.add(new Span(valTok.start(), valTok.end()));
        } else if (keyKind == KeyKind.VALUE) {
            frame.addValueSpan(valTok.start(), valTok.end());
        } else if (keyKind == KeyKind.PATH) {
            if (isSensitiveAttributeOrPath(valTok.decoded())
                    || (!valTok.closed() && mayBeTruncatedSensitivePath(valTok.decoded()))) {
                frame.sawSensitivePath = true;
            } else if (valTok.closed()) {
                frame.sawClosedNonSensitivePath = true;
            }
        }
    }

    private static boolean mayBeTruncatedSensitivePath(String decodedPrefix) {
        if (decodedPrefix == null) {
            return true;
        }
        String trimmed = decodedPrefix.trim().toLowerCase(Locale.ROOT);
        if (trimmed.startsWith("urn:") || "urn:".startsWith(trimmed)) {
            return true;
        }
        int sepIdx = Math.max(trimmed.lastIndexOf(':'), trimmed.lastIndexOf('.'));
        String tail = sepIdx >= 0 ? trimmed.substring(sepIdx + 1) : trimmed;
        return tail.isEmpty() || "password".startsWith(tail) || "authorization".startsWith(tail);
    }

    private static void recordBareFieldValue(ContainerFrame frame,
                                             KeyKind keyKind,
                                             int start,
                                             int end,
                                             String rawVal,
                                             List<Span> spans) {
        if ("null".equals(rawVal)) {
            if (keyKind == KeyKind.PATH) {
                frame.sawClosedNonSensitivePath = true;
            }
            return;
        }
        if (keyKind == KeyKind.SENSITIVE) {
            spans.add(new Span(start, end));
        } else if (keyKind == KeyKind.VALUE) {
            frame.addValueSpan(start, end);
        }
    }

    private static void finishCompositeValue(ContainerFrame parent,
                                             KeyKind boundKey,
                                             int valStart,
                                             int valEnd,
                                             List<Span> spans) {
        if (parent == null || parent.kind != ContainerKind.OBJECT || valEnd <= valStart) {
            return;
        }
        if (boundKey == KeyKind.SENSITIVE) {
            spans.add(new Span(valStart, valEnd));
        } else if (boundKey == KeyKind.VALUE) {
            parent.addValueSpan(valStart, valEnd);
        }
    }

    private static void finalizeObjectFrame(ContainerFrame frame, boolean closed, List<Span> spans) {
        if (frame.valueFieldSpans == null || frame.valueFieldSpans.isEmpty()) {
            return;
        }
        boolean unclosedPatchOpWithoutSafePath = !closed
                && (frame.inOperationsArray || frame.sawOpField)
                && !frame.sawClosedNonSensitivePath;
        if (frame.sawSensitivePath || unclosedPatchOpWithoutSafePath) {
            spans.addAll(frame.valueFieldSpans);
        }
    }

    private static void unwindUnclosedFrames(Deque<ContainerFrame> stack, int eofIdx, List<Span> spans) {
        while (!stack.isEmpty()) {
            ContainerFrame frame = stack.removeLast();
            if (frame.kind == ContainerKind.OBJECT) {
                finalizeObjectFrame(frame, false, spans);
            }
            finishCompositeValue(stack.peekLast(), frame.boundKeyInParent, frame.valStart, eofIdx, spans);
        }
    }

    private static KeyKind classifyKey(String decodedKey) {
        if (decodedKey == null) {
            return KeyKind.OTHER;
        }
        if (isSensitiveAttributeOrPath(decodedKey)) {
            return KeyKind.SENSITIVE;
        }
        String trimmed = decodedKey.trim();
        if ("path".equalsIgnoreCase(trimmed)) {
            return KeyKind.PATH;
        }
        if ("value".equalsIgnoreCase(trimmed)) {
            return KeyKind.VALUE;
        }
        if ("op".equalsIgnoreCase(trimmed)) {
            return KeyKind.OP;
        }
        if ("operations".equalsIgnoreCase(trimmed)) {
            return KeyKind.OPERATIONS;
        }
        return KeyKind.OTHER;
    }

    private static int skipWhitespace(String s, int idx) {
        int n = s.length();
        while (idx < n && Character.isWhitespace(s.charAt(idx))) {
            idx++;
        }
        return idx;
    }

    private static int scanBareToken(String s, int idx) {
        int n = s.length();
        while (idx < n) {
            char c = s.charAt(idx);
            if (Character.isWhitespace(c)
                    || c == ',' || c == '}' || c == ']'
                    || c == '{' || c == '[' || c == '"' || c == ':') {
                break;
            }
            idx++;
        }
        return idx;
    }

    private static StringToken scanQuotedString(String s, int openQuoteIdx) {
        int n = s.length();
        StringBuilder decoded = new StringBuilder(Math.min(64, n - openQuoteIdx));
        int i = openQuoteIdx + 1;
        while (i < n) {
            char c = s.charAt(i);
            if (c == '"') {
                return new StringToken(decoded.toString(), openQuoteIdx, i + 1, true);
            }
            if (c == '\\') {
                if (i + 1 >= n) {
                    return new StringToken(decoded.toString(), openQuoteIdx, n, false);
                }
                i = consumeEscapeSequence(s, i, decoded);
            } else {
                if (decoded.length() < MAX_DECODED_TOKEN_LEN) {
                    decoded.append(c);
                }
                i++;
            }
        }
        return new StringToken(decoded.toString(), openQuoteIdx, n, false);
    }

    private static int consumeEscapeSequence(String s, int backslashIdx, StringBuilder decoded) {
        char esc = s.charAt(backslashIdx + 1);
        if ((esc == 'u' || esc == 'U') && backslashIdx + 5 < s.length()) {
            int codeUnit = parseFourHexDigits(s, backslashIdx + 2);
            if (codeUnit >= 0) {
                if (decoded.length() < MAX_DECODED_TOKEN_LEN) {
                    decoded.append((char) codeUnit);
                }
                return backslashIdx + 6;
            }
        }
        if (decoded.length() < MAX_DECODED_TOKEN_LEN) {
            decoded.append(decodeSimpleEscape(esc));
        }
        return backslashIdx + 2;
    }

    private static int parseFourHexDigits(String s, int start) {
        int value = 0;
        for (int k = 0; k < 4; k++) {
            int digit = Character.digit(s.charAt(start + k), 16);
            if (digit < 0) {
                return -1;
            }
            value = (value << 4) | digit;
        }
        return value;
    }

    private static char decodeSimpleEscape(char esc) {
        return switch (esc) {
            case 'b' -> '\b';
            case 'f' -> '\f';
            case 'n' -> '\n';
            case 'r' -> '\r';
            case 't' -> '\t';
            default -> esc;
        };
    }

    private static String applyReplacementSpans(String s, List<Span> rawSpans) {
        rawSpans.sort(Comparator.comparingInt(Span::start).thenComparing(Comparator.comparingInt(Span::end).reversed()));
        StringBuilder out = new StringBuilder(s.length() + 16);
        int cursor = 0;
        for (Span span : rawSpans) {
            if (span.end() <= cursor) {
                continue;
            }
            int start = Math.max(cursor, span.start());
            out.append(s, cursor, start);
            out.append(QUOTED_REDACTED);
            cursor = span.end();
        }
        if (cursor < s.length()) {
            out.append(s, cursor, s.length());
        }
        return out.toString();
    }

    private String readBody(byte[] body, String encoding) {
        if (body == null || body.length == 0) {
            return null;
        }
        return new String(body, resolveCharset(encoding));
    }

    private static Charset resolveCharset(String encoding) {
        if (!StringUtils.hasText(encoding)) {
            return StandardCharsets.UTF_8;
        }
        try {
            return Charset.forName(encoding.trim());
        } catch (IllegalArgumentException _) {
            return StandardCharsets.UTF_8;
        }
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
