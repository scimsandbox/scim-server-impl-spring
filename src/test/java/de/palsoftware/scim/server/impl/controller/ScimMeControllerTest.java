package de.palsoftware.scim.server.impl.controller;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ScimMeControllerTest {

    private final ScimMeController controller = new ScimMeController();

    @Test
    void meEndpointReturns501() {
        ResponseEntity<Map<String, Object>> response = controller.meNotImplemented(null);

        assertEquals(501, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertEquals("501", response.getBody().get("status"));
        assertEquals("The /Me endpoint is not supported", response.getBody().get("detail"));
    }

    @Test
    void meEndpointReturns501WithCompat() {
        ResponseEntity<Map<String, Object>> response = controller.meNotImplemented("entra");

        assertEquals(501, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertEquals("501", response.getBody().get("status"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void meEndpointResponseIncludesErrorSchema() {
        ResponseEntity<Map<String, Object>> response = controller.meNotImplemented(null);

        assertNotNull(response.getBody());
        var schemas = (java.util.List<String>) response.getBody().get("schemas");
        assertNotNull(schemas);
        assertTrue(schemas.contains("urn:ietf:params:scim:api:messages:2.0:Error"));
    }
}
