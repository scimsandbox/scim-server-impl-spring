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
        Map<?, ?> pagination = (Map<?, ?>) config.get("pagination");
        assertTrue((Boolean) pagination.get("cursor"));
        assertTrue((Boolean) pagination.get("index"));
        assertEquals("index", pagination.get("defaultPaginationMethod"));
        assertEquals(3600, pagination.get("cursorTimeout"));
        assertTrue(config.containsKey("changePassword"));
        Map<?, ?> changePassword = (Map<?, ?>) config.get("changePassword");
        assertEquals(true, changePassword.get("supported"));
        assertTrue(config.containsKey("sort"));
        assertTrue(config.containsKey("etag"));
        assertTrue(config.containsKey("securityEvents"));
        Map<?, ?> securityEvents = (Map<?, ?>) config.get("securityEvents");
        assertEquals(true, securityEvents.get("supported"));
        assertEquals("request", securityEvents.get("asyncRequest"));
        assertTrue(config.containsKey("authenticationSchemes"));
        List<?> authSchemes = (List<?>) config.get("authenticationSchemes");
        assertFalse(authSchemes.isEmpty());
        Map<?, ?> bearerScheme = (Map<?, ?>) authSchemes.get(0);
        assertEquals("https://datatracker.ietf.org/doc/html/rfc6750", bearerScheme.get("documentationUri"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testServiceProviderConfigSchema() {
        Map<String, Object> spcSchema = ScimSchemaDefinitions.getSchemaById("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig");
        assertNotNull(spcSchema);
        List<Map<String, Object>> attrs = (List<Map<String, Object>>) spcSchema.get("attributes");
        Map<String, Object> paginationAttr = attrs.stream()
                .filter(a -> "pagination".equals(a.get("name")))
                .findFirst()
                .orElse(null);
        assertNotNull(paginationAttr);
        List<Map<String, Object>> subAttrs = (List<Map<String, Object>>) paginationAttr.get("subAttributes");
        assertNotNull(subAttrs);
        boolean hasCursorTimeout = subAttrs.stream().anyMatch(sa -> "cursorTimeout".equals(sa.get("name")));
        assertTrue(hasCursorTimeout, "cursorTimeout should be present in schema subAttributes when cursor pagination is enabled");

        Map<String, Object> modeAttr = subAttrs.stream()
                .filter(sa -> "defaultPaginationMethod".equals(sa.get("name")))
                .findFirst()
                .orElse(null);
        assertNotNull(modeAttr);
        assertEquals(List.of("cursor", "index"), modeAttr.get("canonicalValues"));

        Map<String, Object> securityEventsAttr = attrs.stream()
                .filter(a -> "securityEvents".equals(a.get("name")))
                .findFirst()
                .orElse(null);
        assertNotNull(securityEventsAttr);
        List<Map<String, Object>> secSubAttrs = (List<Map<String, Object>>) securityEventsAttr.get("subAttributes");
        assertNotNull(secSubAttrs);
        assertTrue(secSubAttrs.stream().anyMatch(sa -> "supported".equals(sa.get("name"))));
        Map<String, Object> asyncReqAttr = secSubAttrs.stream()
                .filter(sa -> "asyncRequest".equals(sa.get("name")))
                .findFirst()
                .orElse(null);
        assertNotNull(asyncReqAttr);
        assertEquals(List.of("request", "long", "none"), asyncReqAttr.get("canonicalValues"));
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

    @Test
    @SuppressWarnings("unchecked")
    void testExternalIdUniquenessIsNoneAndImsHasOther() {
        Map<String, Object> userSchema = ScimSchemaDefinitions.userSchema();
        List<Map<String, Object>> userAttrs = (List<Map<String, Object>>) userSchema.get("attributes");
        Map<String, Object> userExtId = userAttrs.stream()
                .filter(a -> "externalId".equals(a.get("name")))
                .findFirst().orElseThrow();
        assertEquals("none", userExtId.get("uniqueness"));

        Map<String, Object> imsAttr = userAttrs.stream()
                .filter(a -> "ims".equals(a.get("name")))
                .findFirst().orElseThrow();
        List<Map<String, Object>> imsSub = (List<Map<String, Object>>) imsAttr.get("subAttributes");
        Map<String, Object> imsType = imsSub.stream()
                .filter(sa -> "type".equals(sa.get("name")))
                .findFirst().orElseThrow();
        List<String> canonical = (List<String>) imsType.get("canonicalValues");
        assertTrue(canonical.contains("other"));

        Map<String, Object> groupSchema = ScimSchemaDefinitions.groupSchema();
        List<Map<String, Object>> groupAttrs = (List<Map<String, Object>>) groupSchema.get("attributes");
        Map<String, Object> groupExtId = groupAttrs.stream()
                .filter(a -> "externalId".equals(a.get("name")))
                .findFirst().orElseThrow();
        assertEquals("none", groupExtId.get("uniqueness"));
    }
}
