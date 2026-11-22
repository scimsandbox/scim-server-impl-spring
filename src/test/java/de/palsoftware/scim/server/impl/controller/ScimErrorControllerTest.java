package de.palsoftware.scim.server.impl.controller;

import jakarta.servlet.RequestDispatcher;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import java.sql.SQLException;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ScimErrorControllerTest {

    private final ScimErrorController controller = new ScimErrorController();

    @Test
    void handleError_500_NeverLeaksSqlOrJavaExceptionMessages() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/error");
        request.setAttribute(RequestDispatcher.ERROR_STATUS_CODE, 500);
        request.setAttribute(RequestDispatcher.ERROR_REQUEST_URI, "/ws/123/scim/v2/Users");
        request.setAttribute(RequestDispatcher.ERROR_EXCEPTION,
                new SQLException("ERROR: duplicate key value violates unique constraint on workspace_tokens; jdbc:postgresql://db:5432/scim"));
        request.setAttribute(RequestDispatcher.ERROR_MESSAGE,
                "org.postgresql.util.PSQLException: SELECT token_hash FROM workspace_tokens");

        ResponseEntity<Map<String, Object>> response = controller.handleError(request);

        assertThat(response.getStatusCode().value()).isEqualTo(500);
        Map<String, Object> body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.get("schemas")).isEqualTo(List.of("urn:ietf:params:scim:api:messages:2.0:Error"));
        assertThat(body.get("status")).isEqualTo("500");
        assertThat(body.get("detail")).isEqualTo("An unexpected internal error occurred.");

        String serialized = body.toString();
        assertThat(serialized)
                .doesNotContain("SQLException")
                .doesNotContain("PSQLException")
                .doesNotContain("workspace_tokens")
                .doesNotContain("jdbc:postgresql")
                .doesNotContain("SELECT ");
    }

    @Test
    void handleError_4xxStatuses_UseSafeStaticDescriptions() {
        for (int status : List.of(400, 401, 403, 404, 405, 413, 415, 429)) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/error");
            request.setAttribute(RequestDispatcher.ERROR_STATUS_CODE, status);
            request.setAttribute(RequestDispatcher.ERROR_MESSAGE, "Internal container diagnostic for " + status);

            ResponseEntity<Map<String, Object>> response = controller.handleError(request);

            assertThat(response.getStatusCode().value()).isEqualTo(status);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().get("status")).isEqualTo(String.valueOf(status));
            assertThat(response.getBody().toString()).doesNotContain("Internal container diagnostic");
        }
    }
}
