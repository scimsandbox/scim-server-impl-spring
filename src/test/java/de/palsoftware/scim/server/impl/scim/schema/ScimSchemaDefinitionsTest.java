package de.palsoftware.scim.server.impl.scim.schema;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ScimSchemaDefinitionsTest {

    @Test
    void testServiceProviderConfig() {
        Map<String, Object> config = ScimSchemaDefinitions.serviceProviderConfig();
        assertNotNull(config);
        assertTrue(config.containsKey("schemas"));
        assertTrue(config.containsKey("patch"));
        assertTrue(config.containsKey("bulk"));
        assertTrue(config.containsKey("filter"));
        assertTrue(config.containsKey("pagination"));
        assertTrue(config.containsKey("changePassword"));
        assertTrue(config.containsKey("sort"));
        assertTrue(config.containsKey("etag"));
        assertTrue(config.containsKey("authenticationSchemes"));
    }

    @Test
    void testAllSchemas() {
        List<Map<String, Object>> schemas = ScimSchemaDefinitions.allSchemas();
        assertNotNull(schemas);
        assertEquals(6, schemas.size(), "Should contain 6 schemas");
    }

    @Test
    void testGetSchemaById() {
        Map<String, Object> userSchema = ScimSchemaDefinitions.getSchemaById("urn:ietf:params:scim:schemas:core:2.0:User");
        assertNotNull(userSchema);
        assertEquals("User", userSchema.get("name"));

        Map<String, Object> groupSchema = ScimSchemaDefinitions.getSchemaById("urn:ietf:params:scim:schemas:core:2.0:Group");
        assertNotNull(groupSchema);
        assertEquals("Group", groupSchema.get("name"));

        assertNull(ScimSchemaDefinitions.getSchemaById("unknown"));
    }

    @Test
    void testResourceTypes() {
        List<Map<String, Object>> resourceTypes = ScimSchemaDefinitions.resourceTypes("http://localhost:8080");
        assertNotNull(resourceTypes);
        assertEquals(2, resourceTypes.size(), "Should contain User and Group resource types");
    }

    @Test
    void testGetResourceTypeById() {
        Map<String, Object> userRt = ScimSchemaDefinitions.getResourceTypeById("User");
        assertNotNull(userRt);
        assertEquals("User", userRt.get("name"));

        Map<String, Object> groupRt = ScimSchemaDefinitions.getResourceTypeById("Group", "http://localhost:8080");
        assertNotNull(groupRt);
        assertEquals("Group", groupRt.get("name"));

        assertNull(ScimSchemaDefinitions.getResourceTypeById("unknown"));
    }
}
