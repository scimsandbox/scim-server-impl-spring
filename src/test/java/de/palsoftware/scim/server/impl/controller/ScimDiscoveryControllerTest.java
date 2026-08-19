package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.scim.error.ScimException;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ScimDiscoveryControllerTest {

    private final ScimDiscoveryController controller = new ScimDiscoveryController();

    @Test
    void getServiceProviderConfigReturns200() {
        ResponseEntity<Map<String, Object>> response = controller.getServiceProviderConfig(null);
        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().containsKey("schemas"));
    }

    @Test
    void getSchemasReturns200() {
        ResponseEntity<Map<String, Object>> response = controller.getSchemas(null);
        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertEquals(List.of("urn:ietf:params:scim:api:messages:2.0:ListResponse"), response.getBody().get("schemas"));
    }

    @Test
    void getSchemaByIdNotFoundThrows404() {
        assertThrows(ScimException.class, () -> controller.getSchemaById("unknown-schema", null));
    }

    @Test
    void globalSearchThrows501NotImplemented() {
        ScimException ex = assertThrows(ScimException.class, () ->
                controller.globalSearchNotImplemented("24fb7ccb-3458-44da-b5c8-92b97e2ad702", null));
        assertEquals(501, ex.getHttpStatus());
        assertEquals("Global cross-resource search is not implemented", ex.getMessage());
    }
}
