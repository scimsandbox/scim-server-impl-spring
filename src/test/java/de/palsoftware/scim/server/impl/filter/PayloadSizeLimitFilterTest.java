package de.palsoftware.scim.server.impl.filter;

import de.palsoftware.scim.server.impl.controller.ScimBulkController;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.schema.ScimSchemaDefinitions;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.BufferedReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PayloadSizeLimitFilterTest {

    private PayloadSizeLimitFilter filter;
    private UUID workspaceId;

    @BeforeEach
    void setUp() {
        filter = new PayloadSizeLimitFilter();
        workspaceId = UUID.randomUUID();
    }

    @Test
    void maxPayloadBytesConstant_IsUnifiedAcrossBulkControllerAndServiceProviderConfig() {
        assertThat(PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES).isEqualTo(1_048_576);
        assertThat(ScimBulkController.MAX_PAYLOAD_SIZE).isEqualTo(PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES);
        @SuppressWarnings("unchecked")
        Map<String, Object> bulkConfig = (Map<String, Object>) ScimSchemaDefinitions.serviceProviderConfig().get("bulk");
        assertThat(bulkConfig).containsEntry("maxPayloadSize", PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES);
    }

    @Test
    void nonBulkRequestWithOversizedContentLength_ImmediatelyReturns413WithoutCallingChain() throws Exception {
        MockHttpServletRequest request = fixedLengthRequest(
                "POST",
                "/ws/" + workspaceId + "/scim/v2/Users",
                PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES + 1L);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = Mockito.mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(response.getContentType()).isEqualTo("application/scim+json;charset=UTF-8");
        assertThat(response.getContentAsString())
                .contains("urn:ietf:params:scim:api:messages:2.0:Error")
                .contains("\"status\":\"413\"")
                .contains("Request payload size exceeds maximum allowed size of 1048576 bytes");
        Mockito.verifyNoInteractions(chain);
    }

    @Test
    void bulkPostRequestWithOversizedContentLength_ReturnsBulkSpecific413Detail() throws Exception {
        for (String suffix : new String[]{"/Bulk", "/Bulk/"}) {
            MockHttpServletRequest request = fixedLengthRequest(
                    "POST",
                    "/ws/" + workspaceId + "/scim/v2" + suffix,
                    PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES + 10L);
            MockHttpServletResponse response = new MockHttpServletResponse();
            FilterChain chain = Mockito.mock(FilterChain.class);

            filter.doFilter(request, response, chain);

            assertThat(response.getStatus()).isEqualTo(413);
            assertThat(response.getContentAsString())
                    .contains("\"status\":\"413\"")
                    .contains("Bulk request payload size exceeds maxPayloadSize of 1048576 bytes");
            Mockito.verifyNoInteractions(chain);
        }

        // Non-POST request to /Bulk uses the standard non-Bulk error detail
        MockHttpServletRequest getBulk = fixedLengthRequest(
                "GET",
                "/ws/" + workspaceId + "/scim/v2/Bulk",
                PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES + 1L);
        MockHttpServletResponse getResp = new MockHttpServletResponse();
        filter.doFilter(getBulk, getResp, Mockito.mock(FilterChain.class));
        assertThat(getResp.getStatus()).isEqualTo(413);
        assertThat(getResp.getContentAsString())
                .contains("Request payload size exceeds maximum allowed size of 1048576 bytes");
    }

    @Test
    void bulkRequestStreamExceedingMaxPayloadBytes_AbortsEarlyWith413() throws Exception {
        byte[] oversizedBody = new byte[PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES + 512];
        Arrays.fill(oversizedBody, (byte) 'a');

        HttpServletRequest chunkedBulkRequest = unknownLengthWrapper(
                "POST", "/ws/" + workspaceId + "/scim/v2/Bulk", oversizedBody, null);
        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain chain = (servletRequest, _) -> servletRequest.getInputStream().readAllBytes();

        filter.doFilter(chunkedBulkRequest, response, chain);

        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(response.getContentAsString())
                .contains("urn:ietf:params:scim:api:messages:2.0:Error")
                .contains("\"status\":\"413\"")
                .contains("Bulk request payload size exceeds maxPayloadSize of 1048576 bytes");
    }

    @Test
    void nonBulkChunkedStreamExceeding1MiB_AbortsImmediatelyAtLimitWithoutReadingRemainder() throws Exception {
        int totalStreamSize = PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES * 4; // 4 MiB stream
        AtomicInteger bytesReadFromUnderlying = new AtomicInteger();
        AtomicBoolean closed = new AtomicBoolean();
        AtomicReference<ReadListener> observedListener = new AtomicReference<>();

        MockHttpServletRequest baseRequest = new MockHttpServletRequest("POST", "/ws/" + workspaceId + "/scim/v2/Users");
        baseRequest.setContentType("application/scim+json");
        baseRequest.addHeader("Transfer-Encoding", "chunked");

        HttpServletRequest chunkedRequest = new HttpServletRequestWrapper(baseRequest) {
            @Override
            public int getContentLength() {
                return -1;
            }

            @Override
            public long getContentLengthLong() {
                return -1L;
            }

            @Override
            public ServletInputStream getInputStream() {
                return new ServletInputStream() {
                    private int pos = 0;

                    @Override
                    public boolean isFinished() {
                        return pos >= totalStreamSize;
                    }

                    @Override
                    public boolean isReady() {
                        return true;
                    }

                    @Override
                    public void setReadListener(ReadListener readListener) {
                        observedListener.set(readListener);
                    }

                    @Override
                    public int read() {
                        if (pos >= totalStreamSize) {
                            return -1;
                        }
                        pos++;
                        bytesReadFromUnderlying.incrementAndGet();
                        return 'x';
                    }

                    @Override
                    public int read(byte[] b, int off, int len) {
                        if (pos >= totalStreamSize) {
                            return -1;
                        }
                        int toRead = Math.min(len, Math.min(4096, totalStreamSize - pos));
                        Arrays.fill(b, off, off + toRead, (byte) 'x');
                        pos += toRead;
                        bytesReadFromUnderlying.addAndGet(toRead);
                        return toRead;
                    }

                    @Override
                    public void close() {
                        closed.set(true);
                    }
                };
            }
        };

        MockHttpServletResponse response = new MockHttpServletResponse();
        ReadListener dummyListener = Mockito.mock(ReadListener.class);
        FilterChain chain = (servletRequest, _) -> {
            ServletInputStream in = servletRequest.getInputStream();
            assertThat(servletRequest.getInputStream()).isSameAs(in);
            assertThat(in.isFinished()).isFalse();
            assertThat(in.isReady()).isTrue();
            in.setReadListener(dummyListener);
            try {
                in.readAllBytes();
            } finally {
                in.close();
            }
        };

        filter.doFilter(chunkedRequest, response, chain);

        assertThat(observedListener.get()).isSameAs(dummyListener);
        assertThat(closed).isTrue();
        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(response.getContentAsString())
                .contains("urn:ietf:params:scim:api:messages:2.0:Error")
                .contains("\"status\":\"413\"");
        assertThat(bytesReadFromUnderlying.get()).isLessThanOrEqualTo(PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES + 8192);
    }

    @Test
    void singleByteReadAndGetReader_EnforceLimitAndSupportExplicitAndDefaultCharsets() throws Exception {
        byte[] exactLimitPlusOne = new byte[PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES + 1];
        Arrays.fill(exactLimitPlusOne, (byte) 'z');

        // 1. Single-byte read() up to limit + 1
        HttpServletRequest singleByteReq = unknownLengthWrapper(
                "POST", "/ws/" + workspaceId + "/scim/v2/Users", exactLimitPlusOne, null);
        MockHttpServletResponse singleByteResp = new MockHttpServletResponse();
        filter.doFilter(singleByteReq, singleByteResp, (req, _) -> {
            ServletInputStream in = req.getInputStream();
            byte[] chunk = new byte[PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES - 1];
            int n = in.read(chunk, 0, chunk.length);
            assertThat(n).isEqualTo(chunk.length);
            assertThat(in.read()).isEqualTo('z'); // hits exact limit
            in.read(); // crosses limit -> throws ScimException(413)
        });
        assertThat(singleByteResp.getStatus()).isEqualTo(413);

        // 2. getReader() with explicit ISO-8859-1 encoding exceeding 1 MiB
        HttpServletRequest readerReq = unknownLengthWrapper(
                "POST", "/ws/" + workspaceId + "/scim/v2/Users", exactLimitPlusOne, StandardCharsets.ISO_8859_1.name());
        MockHttpServletResponse readerResp = new MockHttpServletResponse();
        filter.doFilter(readerReq, readerResp, (req, _) -> {
            BufferedReader r1 = req.getReader();
            assertThat(req.getReader()).isSameAs(r1);
            char[] buf = new char[8192];
            while (r1.read(buf) != -1) {
                // drain until limit exceeded
            }
        });
        assertThat(readerResp.getStatus()).isEqualTo(413);

        // 3. getReader() with null/blank encoding falls back to UTF-8 and succeeds within limit
        byte[] validPayload = "{\"userName\":\"alice\"}".getBytes(StandardCharsets.UTF_8);
        HttpServletRequest okReaderReq = unknownLengthWrapper(
                "POST", "/ws/" + workspaceId + "/scim/v2/Users", validPayload, null);
        MockHttpServletResponse okReaderResp = new MockHttpServletResponse();
        AtomicReference<String> readLine = new AtomicReference<>();
        filter.doFilter(okReaderReq, okReaderResp, (req, _) -> {
            readLine.set(req.getReader().readLine());
            // Also verify EOF (-1) on single-byte read does not throw
            assertThat(req.getInputStream().read()).isEqualTo(-1);
        });
        assertThat(okReaderResp.getStatus()).isEqualTo(200);
        assertThat(readLine.get()).isEqualTo("{\"userName\":\"alice\"}");

        // 4. getReader() with unsupported or illegal character encoding throws UnsupportedEncodingException per ServletRequest spec
        for (String invalidEncoding : new String[]{"NO-SUCH-CHARSET-999", "invalid charset!"}) {
            HttpServletRequest badEncodingReq = unknownLengthWrapper(
                    "POST", "/ws/" + workspaceId + "/scim/v2/Users", validPayload, invalidEncoding);
            MockHttpServletResponse badEncodingResp = new MockHttpServletResponse();
            assertThatThrownBy(() -> filter.doFilter(badEncodingReq, badEncodingResp, (req, _) -> req.getReader()))
                    .isInstanceOf(UnsupportedEncodingException.class)
                    .hasMessageContaining(invalidEncoding);
        }
    }

    @Test
    void exactMaxPayloadSize_PassesThroughCleanly() throws Exception {
        byte[] exactPayload = new byte[PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES];
        Arrays.fill(exactPayload, (byte) 'a');

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/ws/" + workspaceId + "/scim/v2/Users");
        request.setContent(exactPayload);
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicInteger downstreamBytes = new AtomicInteger();

        filter.doFilter(request, response, (req, _) -> downstreamBytes.set(req.getInputStream().readAllBytes().length));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(downstreamBytes.get()).isEqualTo(PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES);
    }

    @Test
    void nonScimPaths_AreSkippedWithoutWrapping() throws Exception {
        MockHttpServletRequest actuatorReq = fixedLengthRequest(
                "POST", "/actuator/health", PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES + 999L);
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<HttpServletRequest> observedReq = new AtomicReference<>();

        filter.doFilter(actuatorReq, response, (req, _) -> observedReq.set((HttpServletRequest) req));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(observedReq.get()).isSameAs(actuatorReq);
    }

    @Test
    void downstreamExceptions_Unwrap413WithScimTypeAndRethrowNon413OrCommittedResponses() throws Exception {
        // Wrapped 413 ScimException with scimType is rendered cleanly
        MockHttpServletRequest req1 = new MockHttpServletRequest("POST", "/ws/" + workspaceId + "/scim/v2/Bulk");
        MockHttpServletResponse resp1 = new MockHttpServletResponse();
        filter.doFilter(req1, resp1, (_, _) -> {
            throw new ServletException(new ScimException(413, "tooLarge", "Custom payload error"));
        });
        assertThat(resp1.getStatus()).isEqualTo(413);
        assertThat(resp1.getContentAsString())
                .contains("\"scimType\":\"tooLarge\"")
                .contains("Custom payload error");

        // Non-413 ScimException is rethrown
        MockHttpServletRequest req2 = new MockHttpServletRequest("POST", "/ws/" + workspaceId + "/scim/v2/Users");
        MockHttpServletResponse resp2 = new MockHttpServletResponse();
        assertThatThrownBy(() -> filter.doFilter(req2, resp2, (_, _) -> {
            throw new ScimException(400, "invalidSyntax", "Bad JSON");
        })).isInstanceOf(ScimException.class);

        // Already-committed response rethrows 413 ScimException
        MockHttpServletRequest req3 = new MockHttpServletRequest("POST", "/ws/" + workspaceId + "/scim/v2/Users");
        MockHttpServletResponse resp3 = new MockHttpServletResponse();
        resp3.setCommitted(true);
        assertThatThrownBy(() -> filter.doFilter(req3, resp3, (_, _) -> {
            throw new ScimException(413, null, "Too large after commit");
        })).isInstanceOf(ScimException.class);
    }

    private static MockHttpServletRequest fixedLengthRequest(String method, String uri, long contentLength) {
        MockHttpServletRequest req = new MockHttpServletRequest(method, uri) {
            @Override
            public long getContentLengthLong() {
                return contentLength;
            }

            @Override
            public int getContentLength() {
                return (int) Math.min(Integer.MAX_VALUE, contentLength);
            }
        };
        req.setContentType("application/scim+json");
        req.setContent("{}".getBytes(StandardCharsets.UTF_8));
        return req;
    }

    private static HttpServletRequest unknownLengthWrapper(String method, String uri, byte[] body, String encoding) {
        MockHttpServletRequest base = new MockHttpServletRequest(method, uri);
        base.setContentType("application/scim+json");
        if (encoding != null) {
            base.setCharacterEncoding(encoding);
        }
        base.setContent(body);
        return new HttpServletRequestWrapper(base) {
            @Override
            public int getContentLength() {
                return -1;
            }

            @Override
            public long getContentLengthLong() {
                return -1L;
            }
        };
    }
}
