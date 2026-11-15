package de.palsoftware.scim.server.impl.filter;

import de.palsoftware.scim.server.impl.logging.RequestResponseLoggingFilter;
import de.palsoftware.scim.server.impl.model.ScimRequestLog;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.repository.ScimRequestLogRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
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
import org.mockito.ArgumentCaptor;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PayloadSizeLimitFilterTest {

    private PayloadSizeLimitFilter filter;
    private ServletPayloadStreamGuardFilter streamGuardFilter;
    private UUID workspaceId;

    @BeforeEach
    void setUp() {
        filter = new PayloadSizeLimitFilter();
        streamGuardFilter = new ServletPayloadStreamGuardFilter();
        workspaceId = UUID.randomUUID();
    }

    @Test
    void maxPayloadBytesConstant_IsUnifiedWithServiceProviderConfig() {
        assertThat(PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES).isEqualTo(1_048_576);
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
    void servletPayloadStreamGuardFilter_GuardsPreAuthReadsWhileDeferringNormalUnauthRequests() throws Exception {
        // 1. Normal path where no pre-auth filter reads body: delegates with 0 bytes read so auth returns 401
        MockHttpServletRequest unauthOversized = fixedLengthRequest(
                "PUT",
                "/ws/" + workspaceId + "/scim/v2/Users/" + UUID.randomUUID(),
                PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES + 5000L);
        MockHttpServletResponse unauthResp = new MockHttpServletResponse();
        streamGuardFilter.doFilter(unauthOversized, unauthResp, (_, res) ->
                ((jakarta.servlet.http.HttpServletResponse) res).setStatus(401));
        assertThat(unauthResp.getStatus()).isEqualTo(401);

        // 2. If a pre-auth filter calls getInputStream() or getReader() on fixed-length > 1 MiB -> immediate 413 with 0 bytes read!
        MockHttpServletRequest preAuthStreamReq = fixedLengthRequest(
                "PUT",
                "/ws/" + workspaceId + "/scim/v2/Users/" + UUID.randomUUID(),
                PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES + 1L);
        MockHttpServletResponse preAuthStreamResp = new MockHttpServletResponse();
        streamGuardFilter.doFilter(preAuthStreamReq, preAuthStreamResp, (req, _) -> req.getInputStream());
        assertThat(preAuthStreamResp.getStatus()).isEqualTo(413);
        assertThat(preAuthStreamResp.getContentAsString()).contains("\"status\":\"413\"");

        MockHttpServletRequest preAuthReaderReq = fixedLengthRequest(
                "POST",
                "/ws/" + workspaceId + "/scim/v2/Bulk",
                PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES + 1L);
        MockHttpServletResponse preAuthReaderResp = new MockHttpServletResponse();
        streamGuardFilter.doFilter(preAuthReaderReq, preAuthReaderResp, (req, _) -> req.getReader());
        assertThat(preAuthReaderResp.getStatus()).isEqualTo(413);
        assertThat(preAuthReaderResp.getContentAsString())
                .contains("Bulk request payload size exceeds maxPayloadSize of 1048576 bytes");

        // 3. If a pre-auth filter reads a chunked stream > 1 MiB -> aborts at byte 1,048,577 with 413!
        byte[] chunkedOversized = new byte[PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES + 128];
        Arrays.fill(chunkedOversized, (byte) 'x');
        HttpServletRequest preAuthChunkedReq = unknownLengthWrapper(
                "PUT", "/ws/" + workspaceId + "/scim/v2/Users/" + UUID.randomUUID(), chunkedOversized, null);
        MockHttpServletResponse preAuthChunkedResp = new MockHttpServletResponse();
        streamGuardFilter.doFilter(preAuthChunkedReq, preAuthChunkedResp,
                (req, _) -> req.getInputStream().readAllBytes());
        assertThat(preAuthChunkedResp.getStatus()).isEqualTo(413);

        // 4. Non-SCIM paths skip streamGuardFilter without wrapping
        MockHttpServletRequest actuatorReq = fixedLengthRequest("POST", "/actuator/health", 5_000_000L);
        AtomicReference<HttpServletRequest> observed = new AtomicReference<>();
        streamGuardFilter.doFilter(actuatorReq, new MockHttpServletResponse(),
                (req, _) -> observed.set((HttpServletRequest) req));
        assertThat(observed.get()).isSameAs(actuatorReq);
    }

    @Test
    void loggingBeforePayloadLimit_Persists413StatusAndResponseBodyForBothFixedAndChunkedRequests() throws Exception {
        ScimRequestLogRepository logRepo = Mockito.mock(ScimRequestLogRepository.class);
        WorkspaceRepository wsRepo = Mockito.mock(WorkspaceRepository.class);
        Workspace ws = new Workspace();
        ws.setId(workspaceId);
        when(wsRepo.getReferenceById(workspaceId)).thenReturn(ws);
        when(logRepo.save(any(ScimRequestLog.class))).thenAnswer(inv -> inv.getArgument(0));
        RequestResponseLoggingFilter loggingFilter = new RequestResponseLoggingFilter(logRepo, wsRepo);

        // 1. Fixed Content-Length > 1 MiB Bulk request
        MockHttpServletRequest fixedReq = fixedLengthRequest(
                "POST",
                "/ws/" + workspaceId + "/scim/v2/Bulk",
                PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES + 100L);
        MockHttpServletResponse fixedResp = new MockHttpServletResponse();
        streamGuardFilter.doFilter(fixedReq, fixedResp,
                (r1, s1) -> loggingFilter.doFilter(r1, s1,
                        (r2, s2) -> filter.doFilter(r2, s2, (_, _) -> {})));
        assertThat(fixedResp.getStatus()).isEqualTo(413);

        // 2. Chunked > 1 MiB Bulk request
        byte[] chunkedBytes = new byte[PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES + 200];
        Arrays.fill(chunkedBytes, (byte) 'b');
        HttpServletRequest chunkedReq = unknownLengthWrapper(
                "POST", "/ws/" + workspaceId + "/scim/v2/Bulk", chunkedBytes, null);
        MockHttpServletResponse chunkedResp = new MockHttpServletResponse();
        streamGuardFilter.doFilter(chunkedReq, chunkedResp,
                (r1, s1) -> loggingFilter.doFilter(r1, s1,
                        (r2, s2) -> filter.doFilter(r2, s2, (r3, _) -> r3.getInputStream().readAllBytes())));
        assertThat(chunkedResp.getStatus()).isEqualTo(413);

        ArgumentCaptor<ScimRequestLog> logCaptor = ArgumentCaptor.forClass(ScimRequestLog.class);
        verify(logRepo, Mockito.times(2)).save(logCaptor.capture());
        for (ScimRequestLog entry : logCaptor.getAllValues()) {
            assertThat(entry.getStatus()).isEqualTo(413);
            assertThat(entry.getResponseBody())
                    .contains("\"status\":\"413\"")
                    .contains("Bulk request payload size exceeds maxPayloadSize of 1048576 bytes");
        }
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

        HttpServletRequest singleByteReq = unknownLengthWrapper(
                "POST", "/ws/" + workspaceId + "/scim/v2/Users", exactLimitPlusOne, null);
        MockHttpServletResponse singleByteResp = new MockHttpServletResponse();
        filter.doFilter(singleByteReq, singleByteResp, (req, _) -> {
            ServletInputStream in = req.getInputStream();
            byte[] chunk = new byte[PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES - 1];
            int n = in.read(chunk, 0, chunk.length);
            assertThat(n).isEqualTo(chunk.length);
            assertThat(in.read()).isEqualTo('z');
            in.read();
        });
        assertThat(singleByteResp.getStatus()).isEqualTo(413);

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

        byte[] validPayload = "{\"userName\":\"alice\"}".getBytes(StandardCharsets.UTF_8);
        HttpServletRequest okReaderReq = unknownLengthWrapper(
                "POST", "/ws/" + workspaceId + "/scim/v2/Users", validPayload, null);
        MockHttpServletResponse okReaderResp = new MockHttpServletResponse();
        AtomicReference<String> readLine = new AtomicReference<>();
        filter.doFilter(okReaderReq, okReaderResp, (req, _) -> {
            readLine.set(req.getReader().readLine());
            assertThat(req.getInputStream().read()).isEqualTo(-1);
        });
        assertThat(okReaderResp.getStatus()).isEqualTo(200);
        assertThat(readLine.get()).isEqualTo("{\"userName\":\"alice\"}");

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
        MockHttpServletRequest req1 = new MockHttpServletRequest("POST", "/ws/" + workspaceId + "/scim/v2/Bulk");
        MockHttpServletResponse resp1 = new MockHttpServletResponse();
        filter.doFilter(req1, resp1, (_, _) -> {
            throw new ServletException(new ScimException(413, "tooLarge", "Custom payload error"));
        });
        assertThat(resp1.getStatus()).isEqualTo(413);
        assertThat(resp1.getContentAsString())
                .contains("\"scimType\":\"tooLarge\"")
                .contains("Custom payload error");

        MockHttpServletRequest req2 = new MockHttpServletRequest("POST", "/ws/" + workspaceId + "/scim/v2/Users");
        MockHttpServletResponse resp2 = new MockHttpServletResponse();
        assertThatThrownBy(() -> filter.doFilter(req2, resp2, (_, _) -> {
            throw new ScimException(400, "invalidSyntax", "Bad JSON");
        })).isInstanceOf(ScimException.class);

        MockHttpServletRequest req3 = new MockHttpServletRequest("POST", "/ws/" + workspaceId + "/scim/v2/Users");
        MockHttpServletResponse resp3 = new MockHttpServletResponse();
        resp3.setCommitted(true);
        assertThatThrownBy(() -> filter.doFilter(req3, resp3, (_, _) -> {
            throw new ScimException(413, null, "Too large after commit");
        })).isInstanceOf(ScimException.class);
        assertThatThrownBy(() -> streamGuardFilter.doFilter(req3, resp3, (_, _) -> {
            throw new ScimException(400, "invalidSyntax", "Bad JSON in guard");
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
