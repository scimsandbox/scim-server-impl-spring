package de.palsoftware.scim.server.impl.scim.error;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.mock.http.MockHttpInputMessage;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.transaction.TransactionSystemException;

import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ScimExceptionHandlerTest {

    private final ScimExceptionHandler handler = new ScimExceptionHandler();

    @Test
    // RFC7644-3.12-991537
    void handleTransactionSystemException_sanitizesSqlAndJdbcDetails() {
        SQLException sqlCause = new SQLException(
                "ERROR: relation \"scim_users\" failed on select password from scim_users where jdbc:postgresql://db:5432/scimplayground");
        TransactionSystemException txEx = new TransactionSystemException(
                "Could not commit JPA transaction", sqlCause);

        ResponseEntity<Map<String, Object>> response = handler.handleTransactionSystemException(txEx);

        assertThat(response.getStatusCode().value()).isEqualTo(500);
        Map<String, Object> body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.get("schemas")).isEqualTo(List.of("urn:ietf:params:scim:api:messages:2.0:Error"));
        assertThat(body.get("status")).isEqualTo("500");
        assertThat(body.get("detail")).isEqualTo("Internal server error");

        String serialized = body.toString();
        assertThat(serialized)
                .doesNotContain("scim_users")
                .doesNotContain("jdbc:postgresql")
                .doesNotContain("select ")
                .doesNotContain("SQLException")
                .doesNotContain("Transaction error");
    }

    @Test
    // RFC7644-3.12-991537
    void handleGeneralException_sanitizesInternalExceptionDetails() {
        RuntimeException internalEx = new RuntimeException(
                "NullPointerException at ScimUserService.java:42; secret=scim_playground; insert into workspace_tokens");

        ResponseEntity<Map<String, Object>> response = handler.handleGeneral(internalEx);

        assertThat(response.getStatusCode().value()).isEqualTo(500);
        Map<String, Object> body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.get("schemas")).isEqualTo(List.of("urn:ietf:params:scim:api:messages:2.0:Error"));
        assertThat(body.get("status")).isEqualTo("500");
        assertThat(body.get("detail")).isEqualTo("Internal server error");

        String serialized = body.toString();
        assertThat(serialized)
                .doesNotContain("NullPointerException")
                .doesNotContain(".java:")
                .doesNotContain("scim_playground")
                .doesNotContain("insert ");
    }

    @Test
    void handleIllegalArgumentAnd5xxScimException_sanitizeInternalMessages() {
        IllegalArgumentException iae = new IllegalArgumentException(
                "password cannot be more than 72 bytes; internal class org.springframework.security.crypto.bcrypt.BCrypt");
        ResponseEntity<Map<String, Object>> iaeResp = handler.handleBadRequest(iae);
        assertThat(iaeResp.getStatusCode().value()).isEqualTo(400);
        assertThat(iaeResp.getBody()).isNotNull();
        assertThat(iaeResp.getBody().get("scimType")).isEqualTo("invalidValue");
        assertThat(iaeResp.getBody().toString())
                .doesNotContain("org.springframework")
                .doesNotContain("BCrypt");

        ScimException serverEx = new ScimException(500, null, "SELECT secret FROM scim_users WHERE id=1");
        ResponseEntity<Map<String, Object>> scim500Resp = handler.handleScimException(serverEx);
        assertThat(scim500Resp.getStatusCode().value()).isEqualTo(500);
        assertThat(scim500Resp.getBody()).isNotNull();
        assertThat(scim500Resp.getBody().get("detail")).isEqualTo("Internal server error");
        assertThat(scim500Resp.getBody().toString()).doesNotContain("SELECT secret");
    }

    @Test
    void handleBadJsonAndHandleGeneral_UnwrapNestedScimExceptionAndDataIntegrityViolation() {
        ScimException tooLarge = new ScimException(413, null, "Request payload exceeds maximum allowed size");
        HttpMessageNotReadableException badJsonWithScimCause = new HttpMessageNotReadableException(
                "Could not read JSON", tooLarge, new MockHttpInputMessage(new byte[0]));
        ResponseEntity<Map<String, Object>> unwrapped413 = handler.handleBadJson(badJsonWithScimCause);
        assertThat(unwrapped413.getStatusCode().value()).isEqualTo(413);
        assertThat(unwrapped413.getBody()).isNotNull();
        assertThat(unwrapped413.getBody().get("status")).isEqualTo("413");
        assertThat(unwrapped413.getBody()).doesNotContainKey("scimType");

        HttpMessageNotReadableException plainBadJson = new HttpMessageNotReadableException(
                "Unexpected character", new MockHttpInputMessage("{".getBytes(StandardCharsets.UTF_8)));
        ResponseEntity<Map<String, Object>> syntax400 = handler.handleBadJson(plainBadJson);
        assertThat(syntax400.getStatusCode().value()).isEqualTo(400);
        assertThat(syntax400.getBody()).isNotNull();
        assertThat(syntax400.getBody().get("scimType")).isEqualTo("invalidSyntax");

        RuntimeException wrappedScim = new RuntimeException("Wrapper", new ScimException(409, "uniqueness", "Duplicate userName"));
        ResponseEntity<Map<String, Object>> generalScim = handler.handleGeneral(wrappedScim);
        assertThat(generalScim.getStatusCode().value()).isEqualTo(409);
        assertThat(generalScim.getBody()).isNotNull();
        assertThat(generalScim.getBody().get("scimType")).isEqualTo("uniqueness");

        RuntimeException wrappedDive = new RuntimeException("Wrapper", new DataIntegrityViolationException("unique_idx"));
        ResponseEntity<Map<String, Object>> generalDive = handler.handleGeneral(wrappedDive);
        assertThat(generalDive.getStatusCode().value()).isEqualTo(409);
        assertThat(generalDive.getBody()).isNotNull();
        assertThat(generalDive.getBody().get("scimType")).isEqualTo("uniqueness");
    }

    @Test
    void scimFilterErrorWriter_SerializesErrorsHeadersAndTerminatesOnCyclicCauseChains() throws Exception {
        ObjectMapper mapper = new ObjectMapper();

        MockHttpServletResponse unauthResp = new MockHttpServletResponse();
        ScimFilterErrorWriter.writeScimError(unauthResp, mapper, 401, null, "Missing bearer token");
        assertThat(unauthResp.getStatus()).isEqualTo(401);
        assertThat(unauthResp.getHeader("WWW-Authenticate")).isEqualTo("Bearer");
        assertThat(unauthResp.getContentType()).isEqualTo(ScimFilterErrorWriter.SCIM_CONTENT_TYPE);
        assertThat(unauthResp.getContentAsString())
                .contains(ScimFilterErrorWriter.ERROR_SCHEMA)
                .contains("\"status\":\"401\"")
                .doesNotContain("scimType");

        MockHttpServletResponse rateLimitResp = new MockHttpServletResponse();
        ScimFilterErrorWriter.writeScimError(
                rateLimitResp, mapper, 429, "tooMany", "Rate limit exceeded", "Retry-After", "5");
        assertThat(rateLimitResp.getStatus()).isEqualTo(429);
        assertThat(rateLimitResp.getHeader("Retry-After")).isEqualTo("5");
        assertThat(rateLimitResp.getHeader("WWW-Authenticate")).isNull();
        assertThat(rateLimitResp.getContentAsString())
                .contains("\"status\":\"429\"")
                .contains("\"scimType\":\"tooMany\"");

        // Status-filtered lookup and cyclic cause protection
        ScimException inner413 = new ScimException(413, null, "Too large");
        RuntimeException outer = new RuntimeException("outer", inner413);
        assertThat(ScimFilterErrorWriter.findScimException(outer, 413)).isSameAs(inner413);
        assertThat(ScimFilterErrorWriter.findScimException(outer, 400)).isNull();

        Throwable cycleA = new Throwable("a");
        Throwable cycleB = new Throwable("b", cycleA);
        cycleA.initCause(cycleB);
        assertThat(ScimFilterErrorWriter.findScimException(cycleA)).isNull();
        assertThat(ScimFilterErrorWriter.findScimException(cycleA, 413)).isNull();
        assertThat(ScimFilterErrorWriter.findCause(cycleA, IllegalStateException.class)).isNull();
    }
}
