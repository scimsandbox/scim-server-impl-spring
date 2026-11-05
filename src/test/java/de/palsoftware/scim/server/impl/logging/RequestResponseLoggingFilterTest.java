package de.palsoftware.scim.server.impl.logging;

import de.palsoftware.scim.server.impl.model.ScimRequestLog;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.repository.ScimRequestLogRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
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
}
