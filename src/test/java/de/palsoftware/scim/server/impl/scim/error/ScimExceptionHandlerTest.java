package de.palsoftware.scim.server.impl.scim.error;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.TransactionSystemException;

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
}
