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
import static org.junit.jupiter.api.Assertions.assertSame;
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

    @Test
    void redactPasswords_RedactsPatchAuthorizationPathsSymmetricallyWithPassword() {
        String patchJson = "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],"
                + "\"Operations\":["
                + "{\"op\":\"replace\",\"path\":\"authorization\",\"value\":\"Bearer secret-token-1\"},"
                + "{\"op\":\"replace\",\"value\":\"Bearer secret-token-2\",\"path\":\"urn:example:ext:2.0:User:authorization\"},"
                + "{\"op\":\"replace\",\"path\":\"authorization.token\",\"value\":\"sub-secret-3\"},"
                + "{\"op\":\"replace\",\"path\":\"authorization[type eq \\\"bearer\\\"]\",\"value\":{\"token\":\"filter-secret-4\"}},"
                + "{\"op\":\"replace\",\"path\":\"urn:example:ext:2.0:User:authorization.secret\",\"value\":987654},"
                + "{\"op\":\"replace\",\"path\":\"urn:example:ext:2.0:User:authorization[primary eq true]\",\"value\":[\"arr-secret-5\"]},"
                + "{\"op\":\"replace\",\"path\":\"authorization\",\"value\":null},"
                + "{\"op\":\"replace\",\"path\":\"title\",\"value\":\"VisibleTitle\"}"
                + "]}";

        String redacted = RequestResponseLoggingFilter.redactPasswords(patchJson);

        assertFalse(redacted.contains("secret-token-1"));
        assertFalse(redacted.contains("secret-token-2"));
        assertFalse(redacted.contains("sub-secret-3"));
        assertFalse(redacted.contains("filter-secret-4"));
        assertFalse(redacted.contains("987654"));
        assertFalse(redacted.contains("arr-secret-5"));
        assertTrue(redacted.contains("\"value\":null"));
        assertTrue(redacted.contains("\"VisibleTitle\""));
    }

    @Test
    void redactPasswords_FallbackScannerRedactsUnicodeEscapesAndNonStringSecretValuesInMalformedJson() {
        // 1. Unicode-escaped keys ("pass\u0077ord" and "auth\u006frization") in valid and broken JSON
        String validUnicodeJson = "{\"userName\":\"alice\",\"pass\\u0077ord\":\"UnicodeValidSecret!1\",\"auth\\u006frization\":\"Bearer UnicodeAuth!1\"}";
        String redactedValidUnicode = RequestResponseLoggingFilter.redactPasswords(validUnicodeJson);
        assertFalse(redactedValidUnicode.contains("UnicodeValidSecret!1"));
        assertFalse(redactedValidUnicode.contains("UnicodeAuth!1"));

        String brokenUnicodeJson = "{\"userName\":\"alice\",\"pass\\u0077ord\":\"UnicodeBrokenSecret!2\",\"auth\\u006Frization\":123456789, broken";
        String redactedBrokenUnicode = RequestResponseLoggingFilter.redactPasswords(brokenUnicodeJson);
        assertFalse(redactedBrokenUnicode.contains("UnicodeBrokenSecret!2"));
        assertFalse(redactedBrokenUnicode.contains("123456789"));
        assertTrue(redactedBrokenUnicode.contains("\"[REDACTED]\""));

        // 2. Number, boolean, object, array, and null values on sensitive keys in malformed/truncated JSON
        String brokenMixedValues = "{\"password\":424242,\"Password\":true,\"authorization\":{\"nested\":\"ObjSecret!3\"},"
                + "\"urn:ietf:params:scim:schemas:core:2.0:User:password\":[\"ArrSecret!4\",777],\"password\":null, malformed";
        String redactedMixed = RequestResponseLoggingFilter.redactPasswords(brokenMixedValues);
        assertFalse(redactedMixed.contains("424242"));
        assertFalse(redactedMixed.contains(":true"));
        assertFalse(redactedMixed.contains("ObjSecret!3"));
        assertFalse(redactedMixed.contains("ArrSecret!4"));
        assertFalse(redactedMixed.contains("777"));
        assertTrue(redactedMixed.contains("\"password\":null"));

        // 3. Truncated composite object and array secret values at EOF
        String truncatedObjectSecret = "{\"userName\":\"bob\",\"password\":{\"raw\":\"TruncatedObjSecret!5\",\"extra\":123";
        String redactedTruncatedObj = RequestResponseLoggingFilter.redactPasswords(truncatedObjectSecret);
        assertFalse(redactedTruncatedObj.contains("TruncatedObjSecret!5"));
        assertFalse(redactedTruncatedObj.contains("123"));
        assertTrue(redactedTruncatedObj.contains("\"userName\":\"bob\""));

        String truncatedArraySecret = "{\"userName\":\"bob\",\"authorization\":[\"TruncatedArrSecret!6\",999";
        String redactedTruncatedArr = RequestResponseLoggingFilter.redactPasswords(truncatedArraySecret);
        assertFalse(redactedTruncatedArr.contains("TruncatedArrSecret!6"));
        assertFalse(redactedTruncatedArr.contains("999"));

        // 4. Malformed/truncated PATCH operations with non-string values and authorization paths
        String malformedPatchAuthObj = "{\"Operations\":[{\"op\":\"replace\",\"path\":\"authorization\",\"value\":{\"bearer\":\"PatchObjSecret!7\"}}, broken";
        String redactedPatchAuthObj = RequestResponseLoggingFilter.redactPasswords(malformedPatchAuthObj);
        assertFalse(redactedPatchAuthObj.contains("PatchObjSecret!7"));

        String truncatedOpWithoutPathYet = "{\"Operations\":[{\"op\":\"replace\",\"value\":888999111,\"path\":\"pass\\u0077ord";
        String redactedTruncatedOp = RequestResponseLoggingFilter.redactPasswords(truncatedOpWithoutPathYet);
        assertFalse(redactedTruncatedOp.contains("888999111"));
    }

    @Test
    void redactPasswords_RedactsTruncatedPatchPayloadsWithoutFullSensitiveKeywordAndDotQualifiedParentPaths() {
        // 1. Truncated mid-"password" with NO complete "password"/"authorization"/unicode-escape anywhere in payload
        String truncatedMidPassw = "{\"Operations\":[{\"op\":\"replace\",\"value\":\"Secret1!\",\"path\":\"passw";
        String redacted1 = RequestResponseLoggingFilter.redactPasswords(truncatedMidPassw);
        assertFalse(redacted1.contains("Secret1!"));
        assertTrue(redacted1.contains("\"[REDACTED]\""));

        // 2. Truncated before "path" appears at all (no "password"/"authorization"/unicode-escape anywhere)
        String truncatedBeforePath = "{\"Operations\":[{\"op\":\"replace\",\"value\":\"Secret2!\", ";
        String redacted2 = RequestResponseLoggingFilter.redactPasswords(truncatedBeforePath);
        assertFalse(redacted2.contains("Secret2!"));
        assertTrue(redacted2.contains("\"[REDACTED]\""));

        // 3. Truncated mid-URN before final ":password" segment
        String truncatedMidUrn = "{\"Operations\":[{\"op\":\"replace\",\"value\":\"Secret3!\",\"path\":\"urn:ietf:params:scim:schemas:core:2.0:User";
        String redacted3 = RequestResponseLoggingFilter.redactPasswords(truncatedMidUrn);
        assertFalse(redacted3.contains("Secret3!"));
        assertTrue(redacted3.contains("\"[REDACTED]\""));

        // 4. Truncated dot-qualified path ("nested.auth")
        String truncatedDotPath = "{\"Operations\":[{\"op\":\"replace\",\"value\":\"Secret4!\",\"path\":\"nested.auth";
        String redacted4 = RequestResponseLoggingFilter.redactPasswords(truncatedDotPath);
        assertFalse(redacted4.contains("Secret4!"));
        assertTrue(redacted4.contains("\"[REDACTED]\""));

        // 5. Dot-qualified parent paths ("nested.password", "items[primary eq true].authorization", sub-paths)
        String dotQualifiedPatch = "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],"
                + "\"Operations\":["
                + "{\"op\":\"replace\",\"path\":\"nested.password\",\"value\":\"DotSecret5!\"},"
                + "{\"op\":\"replace\",\"path\":\"items[primary eq true].authorization\",\"value\":\"DotSecret6!\"},"
                + "{\"op\":\"replace\",\"path\":\"nested.password.sub\",\"value\":\"DotSecret7!\"},"
                + "{\"op\":\"replace\",\"path\":\"items[primary eq true].authorization[type eq \\\"bearer\\\"]\",\"value\":\"DotSecret8!\"},"
                + "{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"SafeDisplay\"}"
                + "]}";
        String redactedDot = RequestResponseLoggingFilter.redactPasswords(dotQualifiedPatch);
        assertFalse(redactedDot.contains("DotSecret5!"));
        assertFalse(redactedDot.contains("DotSecret6!"));
        assertFalse(redactedDot.contains("DotSecret7!"));
        assertFalse(redactedDot.contains("DotSecret8!"));
        assertTrue(redactedDot.contains("\"SafeDisplay\""));

        // 6. Trailing backslash at EOF and illegal escape sequence inside PATCH path still redact secrets
        String trailingBackslash = "{\"Operations\":[{\"op\":\"replace\",\"value\":\"BackslashSecret9!\",\"path\":\"\\";
        String redactedBackslash = RequestResponseLoggingFilter.redactPasswords(trailingBackslash);
        assertFalse(redactedBackslash.contains("BackslashSecret9!"));
        assertTrue(redactedBackslash.contains("\"[REDACTED]\""));

        String illegalEscapePatch = "{\"Operations\":[{\"op\":\"replace\",\"value\":\"IllegalEscSecret10!\",\"path\":\"pass\\word\"}]}";
        String redactedIllegalEsc = RequestResponseLoggingFilter.redactPasswords(illegalEscapePatch);
        assertFalse(redactedIllegalEsc.contains("IllegalEscSecret10!"));
        assertTrue(redactedIllegalEsc.contains("\"[REDACTED]\""));

        // 7. Complete valid non-sensitive PATCH fast-paths cleanly without mutating
        String safeCompletePatch = "{\"Operations\":[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"Alice\"}]}";
        assertSame(safeCompletePatch, RequestResponseLoggingFilter.redactPasswords(safeCompletePatch));
    }

    @Test
    void fallbackScanner_DeepArrayMismatchedCloseBraces_RunsInLinearTimeWithAndWithoutEnclosingObject() {
        String warmNoObj = "\"password\"" + "[".repeat(1_500) + "}".repeat(1_500);
        String warmWithObj = "{\"password\":\"s\",\"arr\":" + "[".repeat(1_500) + "}".repeat(1_500);
        for (int w = 0; w < 5; w++) {
            RequestResponseLoggingFilter.redactPasswords(warmNoObj);
            RequestResponseLoggingFilter.redactPasswords(warmWithObj);
        }

        // 1. Without enclosing object: "\"password\"" + "[".repeat(N) + "}".repeat(N)
        String noObj5k = "\"password\"" + "[".repeat(5_000) + "}".repeat(5_000);
        String noObj10k = "\"password\"" + "[".repeat(10_000) + "}".repeat(10_000);
        long noObj5kNanos = bestOfThreeNanos(() -> assertEquals(
                noObj5k, RequestResponseLoggingFilter.redactPasswords(noObj5k)));
        long noObj10kNanos = bestOfThreeNanos(() -> assertEquals(
                noObj10k, RequestResponseLoggingFilter.redactPasswords(noObj10k)));
        assertTrue(noObj10kNanos < 150_000_000L,
                "Expected <150ms on 10k deep array+brace without object, took " + (noObj10kNanos / 1_000_000) + "ms");
        assertTrue(noObj10kNanos <= Math.max(noObj5kNanos * 3L, 15_000_000L),
                "Expected O(n) scaling (5k=" + noObj5kNanos + "ns, 10k=" + noObj10kNanos + "ns)");

        // 2. With enclosing object: "{\"password\":\"s\",\"arr\":" + "[".repeat(N) + "}".repeat(N)
        String withObj5k = "{\"password\":\"s\",\"arr\":" + "[".repeat(5_000) + "}".repeat(5_000);
        String withObj10k = "{\"password\":\"s\",\"arr\":" + "[".repeat(10_000) + "}".repeat(10_000);
        long withObj5kNanos = bestOfThreeNanos(() -> {
            String res = RequestResponseLoggingFilter.redactPasswords(withObj5k);
            assertTrue(res.startsWith("{\"password\":\"[REDACTED]\",\"arr\":"));
            assertFalse(res.contains("\"s\""));
        });
        long withObj10kNanos = bestOfThreeNanos(() -> {
            String res = RequestResponseLoggingFilter.redactPasswords(withObj10k);
            assertTrue(res.startsWith("{\"password\":\"[REDACTED]\",\"arr\":"));
            assertFalse(res.contains("\"s\""));
        });
        assertTrue(withObj10kNanos < 150_000_000L,
                "Expected <150ms on 10k deep array+brace with enclosing object, took "
                        + (withObj10kNanos / 1_000_000) + "ms");
        assertTrue(withObj10kNanos <= Math.max(withObj5kNanos * 3L, 15_000_000L),
                "Expected O(n) scaling (5k=" + withObj5kNanos + "ns, 10k=" + withObj10kNanos + "ns)");
    }

    private static long bestOfThreeNanos(Runnable task) {
        long best = Long.MAX_VALUE;
        for (int run = 0; run < 3; run++) {
            long start = System.nanoTime();
            task.run();
            best = Math.min(best, System.nanoTime() - start);
        }
        return best;
    }

    @Test
    void redactPasswords_FastPathsCompleteNonSensitiveScimPayloadsWithoutReallocating() {
        List<String> safePayloads = List.of(
                new String("{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],"
                        + "\"userName\":\"alice\",\"title\":\"Developer\",\"department\":\"Operations\","
                        + "\"emails\":[{\"value\":\"alice@example.com\",\"type\":\"work\",\"primary\":true}]}"),
                new String("{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Group\"],"
                        + "\"displayName\":\"Ops Team\",\"members\":[{\"value\":\"u1\",\"display\":\"Alice\"}]}"),
                new String("{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:ListResponse\"],"
                        + "\"totalResults\":1,\"Resources\":[{\"id\":\"1\",\"title\":\"Developer\","
                        + "\"groups\":[{\"value\":\"g1\"}]}]}"),
                new String("{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],"
                        + "\"Operations\":[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"Alice Dev\"}]}"),
                new String("{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:BulkRequest\"],"
                        + "\"Operations\":[{\"method\":\"PATCH\",\"path\":\"/Users/1\","
                        + "\"data\":{\"Operations\":[{\"op\":\"replace\",\"path\":\"title\",\"value\":\"Lead\"}]}}]}"),
                new String("{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:Error\"],"
                        + "\"scimType\":\"invalidValue\",\"detail\":\"Invalid attribute value\",\"status\":\"400\"}")
        );

        for (String payload : safePayloads) {
            assertSame(payload, RequestResponseLoggingFilter.redactPasswords(payload));
        }

        // Valid JSON object and array that DO trigger directSensitive ("Password", "\\u") in non-sensitive fields
        // parse via readTree, confirm redactJsonNode == false, and return the original String untouched
        String errorMentioningPassword = new String(
                "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:Error\"],"
                        + "\"detail\":\"Password must not exceed 72 UTF-8 bytes\",\"status\":\"400\"}");
        String unicodeArrayNoSecret = new String("[{\"displayName\":\"M\\u00fcller\"}]");
        assertSame(errorMentioningPassword, RequestResponseLoggingFilter.redactPasswords(errorMentioningPassword));
        assertSame(unicodeArrayNoSecret, RequestResponseLoggingFilter.redactPasswords(unicodeArrayNoSecret));

        assertEquals("", RequestResponseLoggingFilter.redactPasswords(""));
        assertEquals(null, RequestResponseLoggingFilter.redactPasswords(null));
    }

    @Test
    void isStructurallyCompleteJson_ValidatesBalancedContainersStringsEscapesAndDepthLimits() {
        // Valid balanced objects, arrays, escapes, and depth-64 boundary
        assertTrue(RequestResponseLoggingFilter.isStructurallyCompleteJson("{}"));
        assertTrue(RequestResponseLoggingFilter.isStructurallyCompleteJson("  [ 1, true, null, {\"k\":\"v\"} ] \n\t "));
        assertTrue(RequestResponseLoggingFilter.isStructurallyCompleteJson(
                "{\"escaped\":\"quote:\\\" slash:\\\\ solidus:\\/ ctrl:\\b\\f\\n\\r\\t hex:\\u0041\\u007a braces:{}[]\"}"));
        assertTrue(RequestResponseLoggingFilter.isStructurallyCompleteJson("[".repeat(64) + "]".repeat(64)));

        // Null, blank, scalar, non-container roots
        assertFalse(RequestResponseLoggingFilter.isStructurallyCompleteJson(null));
        assertFalse(RequestResponseLoggingFilter.isStructurallyCompleteJson(""));
        assertFalse(RequestResponseLoggingFilter.isStructurallyCompleteJson("   \t\n  "));
        assertFalse(RequestResponseLoggingFilter.isStructurallyCompleteJson("123"));
        assertFalse(RequestResponseLoggingFilter.isStructurallyCompleteJson("\"string-scalar\""));
        assertFalse(RequestResponseLoggingFilter.isStructurallyCompleteJson("}orphan"));

        // Truncated/unclosed strings and invalid escapes
        assertFalse(RequestResponseLoggingFilter.isStructurallyCompleteJson("{\"a\":\"unclosed}"));
        assertFalse(RequestResponseLoggingFilter.isStructurallyCompleteJson("{\"a\":\"trailing-backslash\\"));
        assertFalse(RequestResponseLoggingFilter.isStructurallyCompleteJson("{\"a\":\"escaped-quote-at-eof\\\""));
        assertFalse(RequestResponseLoggingFilter.isStructurallyCompleteJson("{\"a\":\"illegal-escape\\w\"}"));
        assertFalse(RequestResponseLoggingFilter.isStructurallyCompleteJson("{\"a\":\"short-unicode\\u12\"}"));
        assertFalse(RequestResponseLoggingFilter.isStructurallyCompleteJson("{\"a\":\"bad-unicode\\uZZZZ\"}"));

        // Mismatched brackets, unclosed containers, trailing tokens, and depth > 64
        assertFalse(RequestResponseLoggingFilter.isStructurallyCompleteJson("{]"));
        assertFalse(RequestResponseLoggingFilter.isStructurallyCompleteJson("[}"));
        assertFalse(RequestResponseLoggingFilter.isStructurallyCompleteJson("{\"a\":[1,2}}"));
        assertFalse(RequestResponseLoggingFilter.isStructurallyCompleteJson("{\"a\":[1,2]"));
        assertFalse(RequestResponseLoggingFilter.isStructurallyCompleteJson("{\"a\":1} trailing"));
        assertFalse(RequestResponseLoggingFilter.isStructurallyCompleteJson("{\"a\":1}{}"));
        assertFalse(RequestResponseLoggingFilter.isStructurallyCompleteJson("[".repeat(65) + "]".repeat(65)));
    }

    @Test
    void invalidOrUnsupportedRequestCharset_FallsBackToUtf8WithoutMaskingClientErrorStatus() throws Exception {
        String rawPayload = "{\"userName\":\"alice\",\"password\":\"CharsetSecret!9\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/ws/" + workspaceId + "/scim/v2/Users") {
            @Override
            public String getCharacterEncoding() {
                return "BOGUS;illegal!charset";
            }
        };
        request.setContentType("application/scim+json");
        request.setContent(rawPayload.getBytes(StandardCharsets.UTF_8));

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain chain = (req, res) -> {
            req.getInputStream().readAllBytes();
            HttpServletResponse httpRes = (HttpServletResponse) res;
            httpRes.setStatus(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);
            httpRes.getOutputStream().write("{\"status\":\"415\"}".getBytes(StandardCharsets.UTF_8));
        };

        filter.doFilter(request, response, chain);

        assertEquals(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE, response.getStatus());
        ArgumentCaptor<ScimRequestLog> logCaptor = ArgumentCaptor.forClass(ScimRequestLog.class);
        verify(logRepository).save(logCaptor.capture());

        ScimRequestLog saved = logCaptor.getValue();
        assertEquals(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE, saved.getStatus());
        assertFalse(saved.getRequestBody().contains("CharsetSecret!9"));
        assertTrue(saved.getRequestBody().contains("\"[REDACTED]\""));
    }
}
