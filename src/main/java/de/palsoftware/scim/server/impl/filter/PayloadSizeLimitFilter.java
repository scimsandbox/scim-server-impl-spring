package de.palsoftware.scim.server.impl.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.security.RequestPaths;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Enforces the 1 MiB SCIM request body limit across both fixed-length ({@code Content-Length})
 * and streaming/chunked requests before request body buffering or controller deserialization.
 */
@Component
public class PayloadSizeLimitFilter extends OncePerRequestFilter {

    public static final int MAX_PAYLOAD_BYTES = 1_048_576; // 1 MiB

    private final ObjectMapper objectMapper;

    @Autowired
    public PayloadSizeLimitFilter(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    }

    public PayloadSizeLimitFilter() {
        this(new ObjectMapper());
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !RequestPaths.isScimPath(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String payloadLimitDetail = isBulkPostRequest(request)
                ? "Bulk request payload size exceeds maxPayloadSize of " + MAX_PAYLOAD_BYTES + " bytes"
                : "Request payload size exceeds maximum allowed size of " + MAX_PAYLOAD_BYTES + " bytes";

        if (request.getContentLengthLong() > MAX_PAYLOAD_BYTES) {
            writeScimErrorResponse(response, HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                    null, payloadLimitDetail);
            return;
        }

        HttpServletRequest boundedRequest = new BoundedPayloadRequestWrapper(
                request, MAX_PAYLOAD_BYTES, payloadLimitDetail);
        try {
            filterChain.doFilter(boundedRequest, response);
        } catch (ServletException | IOException | RuntimeException ex) {
            ScimException payloadEx = findScimExceptionByStatus(ex, HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
            if (payloadEx != null && !response.isCommitted()) {
                response.resetBuffer();
                writeScimErrorResponse(response, HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                        payloadEx.getScimType(), payloadEx.getMessage());
                return;
            }
            throw ex;
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

    private void writeScimErrorResponse(HttpServletResponse response,
                                        int status,
                                        String scimType,
                                        String detail) throws IOException {
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
        response.getWriter().write(objectMapper.writeValueAsString(error));
        response.getWriter().flush();
    }

    private static final class BoundedPayloadRequestWrapper extends HttpServletRequestWrapper {
        private final int maxBytes;
        private final String errorDetail;
        private ServletInputStream boundedInputStream;
        private BufferedReader boundedReader;

        BoundedPayloadRequestWrapper(HttpServletRequest request, int maxBytes, String errorDetail) {
            super(request);
            this.maxBytes = maxBytes;
            this.errorDetail = errorDetail;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (boundedInputStream == null) {
                ServletInputStream delegate = super.getInputStream();
                boundedInputStream = new BoundedServletInputStream(delegate, maxBytes, errorDetail);
            }
            return boundedInputStream;
        }

        @Override
        public BufferedReader getReader() throws IOException {
            if (boundedReader == null) {
                Charset cs = resolveCharset(getCharacterEncoding());
                boundedReader = new BufferedReader(new InputStreamReader(getInputStream(), cs));
            }
            return boundedReader;
        }

        private static Charset resolveCharset(String enc) throws UnsupportedEncodingException {
            if (!StringUtils.hasText(enc)) {
                return StandardCharsets.UTF_8;
            }
            try {
                return Charset.forName(enc);
            } catch (IllegalArgumentException _) {
                throw new UnsupportedEncodingException(enc);
            }
        }
    }

    private static final class BoundedServletInputStream extends ServletInputStream {
        private final ServletInputStream delegate;
        private final int maxBytes;
        private final String errorDetail;
        private long bytesRead;

        BoundedServletInputStream(ServletInputStream delegate, int maxBytes, String errorDetail) {
            this.delegate = delegate;
            this.maxBytes = maxBytes;
            this.errorDetail = errorDetail;
        }

        private void addBytes(int count) {
            if (count > 0) {
                bytesRead += count;
                if (bytesRead > maxBytes) {
                    throw new ScimException(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                            null, errorDetail);
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
    }
}
