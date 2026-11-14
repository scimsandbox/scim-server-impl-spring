package de.palsoftware.scim.server.impl.logging;

import de.palsoftware.scim.server.impl.model.ScimRequestLog;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.repository.ScimRequestLogRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * White-box unit tests for password redaction in {@link RequestResponseLoggingFilter}.
 * Traceability: RFC7643-9.2-287493, RFC7643-4.1.1-6515f1, RFC7643-4.1.1-328207, RFC7643-9.2-e4d59c, RFC7644-7.7-f11467.
 */
class RequestResponseLoggingFilterTest {

    private ScimRequestLogRepository logRepository;
    private WorkspaceRepository workspaceRepository;
    private RequestResponseLoggingFilter filter;
    private UUID workspaceId;

    @BeforeEach
    void setUp() {
        logRepository = Mockito.mock(ScimRequestLogRepository.class);
        workspaceRepository = Mockito.mock(WorkspaceRepository.class);
        filter = new RequestResponseLoggingFilter(logRepository, workspaceRepository);
        workspaceId = UUID.randomUUID();

        Workspace workspace = new Workspace();
        workspace.setId(workspaceId);

        when(workspaceRepository.getReferenceById(workspaceId)).thenReturn(workspace);
        when(logRepository.save(any(ScimRequestLog.class))).thenAnswer(invocation -> invocation.getArgument(0));
    }

    /**
     * Updated from the legacy {@code requestAndResponseBodies_AreStoredWithoutRedaction} test, which
     * previously asserted non-RFC behavior (storing cleartext passwords in {@code scim_request_logs}).
     * Corrected per RFC 7643 §9.2 (RFC7643-9.2-287493): password values MUST NOT be stored in cleartext
     * in persisted request/response logs, while live servlet streams remain untouched for downstream handlers.
     */
    @Test
    void requestAndResponseBodies_RedactPasswordsWithoutMutatingLiveStreams() throws Exception {
        // RFC7643-9.2-287493, RFC7643-4.1.1-328207, RFC7643-9.2-e4d59c, RFC7644-7.7-f11467
        String rawRequestPayload = "{\"userName\":\"alice\",\"password\":\"s\\\"ecret\","
                + "\"nested\":{\"Password\":\"another-secret\"},"
                + "\"urn:ietf:params:scim:schemas:core:2.0:User:password\":\"urn-secret\"}";
        String rawResponsePayload = "{\"password\":\"reply-secret\",\"detail\":\"created\"}";

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        request.setRequestURI("/ws/" + workspaceId + "/scim/v2/Users");
        request.setCharacterEncoding(StandardCharsets.UTF_8.name());
        request.setContentType("application/scim+json");
        request.setContent(rawRequestPayload.getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();

        AtomicReference<String> downstreamReadBody = new AtomicReference<>();
        FilterChain chain = (servletRequest, servletResponse) -> {
            byte[] bytes = servletRequest.getInputStream().readAllBytes();
            downstreamReadBody.set(new String(bytes, StandardCharsets.UTF_8));
            HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
            httpServletResponse.setCharacterEncoding(StandardCharsets.UTF_8.name());
            httpServletResponse.setStatus(HttpServletResponse.SC_CREATED);
            httpServletResponse.getWriter().write(rawResponsePayload);
        };

        filter.doFilter(request, response, chain);

        // Downstream controller MUST receive the unmutated cleartext password from the live stream
        assertEquals(rawRequestPayload, downstreamReadBody.get());
        // Client HTTP response stream MUST remain untouched
        assertEquals(rawResponsePayload, response.getContentAsString());

        ArgumentCaptor<ScimRequestLog> logCaptor = ArgumentCaptor.forClass(ScimRequestLog.class);
        verify(logRepository).save(logCaptor.capture());

        ScimRequestLog savedLog = logCaptor.getValue();
        assertEquals(
                "{\"userName\":\"alice\",\"password\":\"[REDACTED]\","
                        + "\"nested\":{\"Password\":\"[REDACTED]\"},"
                        + "\"urn:ietf:params:scim:schemas:core:2.0:User:password\":\"[REDACTED]\"}",
                savedLog.getRequestBody());
        assertEquals("{\"password\":\"[REDACTED]\",\"detail\":\"created\"}", savedLog.getResponseBody());
        assertFalse(savedLog.getRequestBody().contains("s\\\"ecret"));
        assertFalse(savedLog.getRequestBody().contains("another-secret"));
        assertFalse(savedLog.getRequestBody().contains("urn-secret"));
        assertFalse(savedLog.getResponseBody().contains("reply-secret"));
        assertEquals(HttpServletResponse.SC_CREATED, savedLog.getStatus());
    }

    @Test
    void redactPasswords_HandlesPatchOperationsWithPathAndValueMap() {
        // RFC7643-9.2-287493, RFC7643-4.1.1-328207
        String patchJson = "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],"
                + "\"Operations\":["
                + "{\"op\":\"replace\",\"path\":\"password\",\"value\":\"Secret!1\"},"
                + "{\"op\":\"replace\",\"value\":\"Secret!1b\",\"path\":\"urn:ietf:params:scim:schemas:core:2.0:User:password\"},"
                + "{\"op\":\"add\",\"value\":{\"password\":\"Secret!2\",\"displayName\":\"Alice\"}},"
                + "{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"UnchangedDisplay\"}"
                + "]}";

        String redacted = RequestResponseLoggingFilter.redactPasswords(patchJson);

        assertFalse(redacted.contains("Secret!1"));
        assertFalse(redacted.contains("Secret!1b"));
        assertFalse(redacted.contains("Secret!2"));
        assertTrue(redacted.contains("\"displayName\":\"Alice\""));
        assertTrue(redacted.contains("\"value\":\"UnchangedDisplay\""));
        assertTrue(redacted.contains("\"[REDACTED]\""));
    }

    @Test
    void redactPasswords_HandlesBulkRequestWithPostAndPatchOperations() {
        // RFC7643-9.2-287493, RFC7644-7.7-f11467
        String bulkJson = "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:BulkRequest\"],"
                + "\"Operations\":["
                + "{\"method\":\"POST\",\"path\":\"/Users\",\"bulkId\":\"u1\","
                + "\"data\":{\"userName\":\"bob\",\"Password\":\"BulkPostSecret!9\"}},"
                + "{\"method\":\"PATCH\",\"path\":\"/Users/123\","
                + "\"data\":{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],"
                + "\"Operations\":[{\"op\":\"replace\",\"path\":\"password\",\"value\":\"BulkPatchSecret!8\"},"
                + "{\"op\":\"add\",\"value\":{\"password\":\"BulkAddSecret!7\",\"title\":\"Staff\"}}]}}"
                + "]}";

        String redacted = RequestResponseLoggingFilter.redactPasswords(bulkJson);

        assertFalse(redacted.contains("BulkPostSecret!9"));
        assertFalse(redacted.contains("BulkPatchSecret!8"));
        assertFalse(redacted.contains("BulkAddSecret!7"));
        assertTrue(redacted.contains("\"userName\":\"bob\""));
        assertTrue(redacted.contains("\"title\":\"Staff\""));
    }

    @Test
    void redactPasswords_HandlesMalformedAndTruncatedJsonPayloads() {
        // RFC7643-9.2-287493
        String malformedCompleteQuote = "{\"userName\":\"alice\", \"password\" : \"Secret!3\" , broken";
        String redacted1 = RequestResponseLoggingFilter.redactPasswords(malformedCompleteQuote);
        assertFalse(redacted1.contains("Secret!3"));
        assertTrue(redacted1.contains("\"userName\":\"alice\""));
        assertTrue(redacted1.contains("\"[REDACTED]\""));

        String truncatedMidPassword = "{\"userName\":\"alice\",\"Password\":\"TruncatedSecret!4";
        String redacted2 = RequestResponseLoggingFilter.redactPasswords(truncatedMidPassword);
        assertFalse(redacted2.contains("TruncatedSecret!4"));
        assertTrue(redacted2.contains("\"[REDACTED]\""));

        String malformedPatch = "{\"Operations\":[{\"op\":\"replace\",\"path\":\"password\",\"value\":\"PatchMalformed!5\"";
        String redacted3 = RequestResponseLoggingFilter.redactPasswords(malformedPatch);
        assertFalse(redacted3.contains("PatchMalformed!5"));
        assertTrue(redacted3.contains("\"[REDACTED]\""));

        String pathOpValueTruncated = "{\"Operations\":[{\"path\":\"password\",\"op\":\"replace\",\"value\":\"PathOpValueSecret!6";
        String redacted4 = RequestResponseLoggingFilter.redactPasswords(pathOpValueTruncated);
        assertFalse(redacted4.contains("PathOpValueSecret!6"));
        assertTrue(redacted4.contains("\"[REDACTED]\""));

        String valueOpPathTruncated = "{\"Operations\":[{\"value\":\"ValueOpPathSecret!7\",\"op\":\"replace\",\"path\":\"urn:ietf:params:scim:schemas:core:2.0:User:password\"";
        String redacted5 = RequestResponseLoggingFilter.redactPasswords(valueOpPathTruncated);
        assertFalse(redacted5.contains("ValueOpPathSecret!7"));
        assertTrue(redacted5.contains("\"[REDACTED]\""));

        String multiOpMalformed = "{\"Operations\":[{\"path\":\"displayName\",\"op\":\"replace\",\"value\":\"KeepThisName\"},{\"path\":\"password\",\"op\":\"add\",\"value\":\"HideThisSecret!8";
        String redacted6 = RequestResponseLoggingFilter.redactPasswords(multiOpMalformed);
        assertTrue(redacted6.contains("KeepThisName"));
        assertFalse(redacted6.contains("HideThisSecret!8"));
        assertTrue(redacted6.contains("\"[REDACTED]\""));
    }

    @Test
    void redactPasswords_PreservesPayloadWithoutPasswordsUntouched() {
        // RFC7643-9.2-287493
        String nonPasswordJson = "{\"userName\":\"carol\",\"displayName\":\"Carol Dan\"}";
        assertEquals(nonPasswordJson, RequestResponseLoggingFilter.redactPasswords(nonPasswordJson));
    }

    @Test
    void redactWithRegexFallback_LinearTimeOnAdversarialMalformedInput() {
        // 20,000-character malformed JSON payload with repeated "value":"..." segments and unclosed quotes
        StringBuilder sb = new StringBuilder(22_000);
        sb.append("{\"Operations\":[");
        for (int i = 0; i < 400; i++) {
            sb.append("{\"op\":\"replace\",\"value\":\"")
              .append("a".repeat(30))
              .append("\",\"extra\":\"unclosed");
        }
        sb.append("{\"op\":\"replace\",\"path\":\"password\",\"value\":\"FinalSecret!99");
        String adversarial = sb.toString();

        long startNanos = System.nanoTime();
        String redacted = RequestResponseLoggingFilter.redactPasswords(adversarial);
        long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000;

        assertFalse(redacted.contains("FinalSecret!99"));
        assertTrue(redacted.contains("\"[REDACTED]\""));
        assertTrue(elapsedMs < 500, "Expected linear-time redaction (<500ms), took " + elapsedMs + "ms");
    }

    @Test
    void nonScimAndMalformedWorkspacePaths_SkipLogPersistenceWithoutBreakingResponse() throws Exception {
        MockHttpServletRequest actuatorReq = new MockHttpServletRequest("GET", "/actuator/health");
        MockHttpServletResponse actuatorResp = new MockHttpServletResponse();
        filter.doFilter(actuatorReq, actuatorResp, (_, res) -> ((HttpServletResponse) res).setStatus(200));
        Mockito.verifyNoInteractions(logRepository);

        MockHttpServletRequest nonUuidScimReq = new MockHttpServletRequest("GET", "/ws/not-a-uuid/scim/v2/Users");
        MockHttpServletResponse nonUuidScimResp = new MockHttpServletResponse();
        filter.doFilter(nonUuidScimReq, nonUuidScimResp, (_, res) -> {
            ((HttpServletResponse) res).setStatus(404);
            res.getWriter().write("{\"status\":\"404\"}");
        });
        assertEquals(404, nonUuidScimResp.getStatus());
        assertEquals("{\"status\":\"404\"}", nonUuidScimResp.getContentAsString());
        Mockito.verifyNoInteractions(logRepository);
    }

    @Test
    void redactPasswords_AlsoRedactsAuthorizationFieldsAndNeverPersistsAuthHeader() throws Exception {
        String payload = "{\"userName\":\"alice\",\"authorization\":\"Bearer secret-jwt\",\"Authorization\":\"Basic abc\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/ws/" + workspaceId + "/scim/v2/Users");
        request.setContentType("application/scim+json");
        request.addHeader("Authorization", "Bearer top-secret-workspace-token");
        request.setContent(payload.getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain chain = (req, res) -> {
            req.getInputStream().readAllBytes();
            ((HttpServletResponse) res).setStatus(201);
            res.getWriter().write("{\"id\":\"1\"}");
        };

        filter.doFilter(request, response, chain);

        ArgumentCaptor<ScimRequestLog> logCaptor = ArgumentCaptor.forClass(ScimRequestLog.class);
        verify(logRepository).save(logCaptor.capture());
        ScimRequestLog saved = logCaptor.getValue();
        assertFalse(saved.getRequestBody().contains("secret-jwt"));
        assertFalse(saved.getRequestBody().contains("Basic abc"));
        assertFalse(saved.getRequestBody().contains("top-secret-workspace-token"));
        assertTrue(saved.getRequestBody().contains("\"[REDACTED]\""));
    }

    @Test
    void uncaughtScimExceptionAndRuntimeException_LogActualErrorStatusInsteadOfDefault200() {
        // 1. Uncaught ScimException(413) logs status 413
        MockHttpServletRequest scimExReq = new MockHttpServletRequest("POST", "/ws/" + workspaceId + "/scim/v2/Users");
        MockHttpServletResponse scimExResp = new MockHttpServletResponse();
        assertThrows(ScimException.class, () -> filter.doFilter(scimExReq, scimExResp, (_, _) -> {
            throw new ScimException(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE, null, "Payload too large");
        }));

        // 2. Wrapped ScimException(413) inside ServletException also logs status 413
        MockHttpServletRequest wrappedScimExReq = new MockHttpServletRequest("POST", "/ws/" + workspaceId + "/scim/v2/Bulk");
        MockHttpServletResponse wrappedScimExResp = new MockHttpServletResponse();
        assertThrows(ServletException.class, () -> filter.doFilter(wrappedScimExReq, wrappedScimExResp, (_, _) -> {
            throw new ServletException(new ScimException(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE, null, "Bulk payload too large"));
        }));

        // 3. Uncaught RuntimeException logs status 500 (never 200)
        MockHttpServletRequest runtimeExReq = new MockHttpServletRequest("GET", "/ws/" + workspaceId + "/scim/v2/Users");
        MockHttpServletResponse runtimeExResp = new MockHttpServletResponse();
        assertThrows(IllegalStateException.class, () -> filter.doFilter(runtimeExReq, runtimeExResp, (_, _) -> {
            throw new IllegalStateException("Unexpected failure");
        }));

        // 4. Pre-populated >=400 response status is preserved when an exception unwinds
        MockHttpServletRequest presetStatusReq = new MockHttpServletRequest("PATCH", "/ws/" + workspaceId + "/scim/v2/Users/1");
        MockHttpServletResponse presetStatusResp = new MockHttpServletResponse();
        assertThrows(RuntimeException.class, () -> filter.doFilter(presetStatusReq, presetStatusResp, (_, res) -> {
            ((HttpServletResponse) res).setStatus(HttpServletResponse.SC_BAD_GATEWAY);
            throw new RuntimeException("Upstream error");
        }));

        ArgumentCaptor<ScimRequestLog> logCaptor = ArgumentCaptor.forClass(ScimRequestLog.class);
        verify(logRepository, Mockito.times(4)).save(logCaptor.capture());
        List<ScimRequestLog> savedLogs = logCaptor.getAllValues();

        assertEquals(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE, savedLogs.get(0).getStatus());
        assertEquals(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE, savedLogs.get(1).getStatus());
        assertEquals(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, savedLogs.get(2).getStatus());
        assertEquals(HttpServletResponse.SC_BAD_GATEWAY, savedLogs.get(3).getStatus());
    }
}
