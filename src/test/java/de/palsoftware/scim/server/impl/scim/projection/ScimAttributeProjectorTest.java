package de.palsoftware.scim.server.impl.scim.projection;

import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class ScimAttributeProjectorTest {

    private Map<String, Object> buildSampleUserResource() {
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("schemas", List.of(
                "urn:ietf:params:scim:schemas:core:2.0:User",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"));
        res.put("id", "11111111-1111-1111-1111-111111111111");
        res.put("userName", "bjensen");
        res.put("password", "shouldNeverAppear");

        Map<String, Object> name = new LinkedHashMap<>();
        name.put("givenName", "Barbara");
        name.put("familyName", "Jensen");
        name.put("formatted", "Barbara Jensen");
        res.put("name", name);

        List<Map<String, Object>> emails = new ArrayList<>();
        Map<String, Object> e1 = new LinkedHashMap<>();
        e1.put("value", "bjensen@example.com");
        e1.put("type", "work");
        e1.put("primary", true);
        emails.add(e1);
        res.put("emails", emails);

        Map<String, Object> ent = new LinkedHashMap<>();
        ent.put("department", "Engineering");
        Map<String, Object> mgr = new LinkedHashMap<>();
        mgr.put("value", "22222222-2222-2222-2222-222222222222");
        mgr.put("displayName", "Alice Boss");
        ent.put("manager", mgr);
        res.put("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", ent);

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("resourceType", "User");
        meta.put("version", "W/\"1\"");
        res.put("meta", meta);
        return res;
    }

    @Test
    @SuppressWarnings("unchecked")
    void testAttributesSubPathInclusion() {
        Map<String, Object> res = buildSampleUserResource();
        ScimAttributeProjector.applyProjection(res, "userName,name.givenName,emails.value", null);

        assertFalse(res.containsKey("password"));
        assertTrue(res.containsKey("schemas"));
        assertTrue(res.containsKey("id"));
        assertTrue(res.containsKey("meta"));
        assertEquals("bjensen", res.get("userName"));

        Map<String, Object> name = (Map<String, Object>) res.get("name");
        assertNotNull(name);
        assertEquals(Map.of("givenName", "Barbara"), name);

        List<Map<String, Object>> emails = (List<Map<String, Object>>) res.get("emails");
        assertNotNull(emails);
        assertEquals(1, emails.size());
        assertEquals(Map.of("value", "bjensen@example.com"), emails.get(0));

        assertFalse(res.containsKey("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testUrnPrefixedCoreAndEnterpriseSubAttributes() {
        Map<String, Object> res = buildSampleUserResource();
        ScimAttributeProjector.applyProjection(res,
                "urn:ietf:params:scim:schemas:core:2.0:User:name.familyName,"
                        + "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value",
                null);

        Map<String, Object> name = (Map<String, Object>) res.get("name");
        assertEquals(Map.of("familyName", "Jensen"), name);

        Map<String, Object> ent = (Map<String, Object>) res.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User");
        assertNotNull(ent);
        assertFalse(ent.containsKey("department"));
        Map<String, Object> mgr = (Map<String, Object>) ent.get("manager");
        assertEquals(Map.of("value", "22222222-2222-2222-2222-222222222222"), mgr);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testExcludedAttributesSubPathsAndAlwaysReturned() {
        Map<String, Object> res = buildSampleUserResource();
        ScimAttributeProjector.applyProjection(res, null, "id,schemas,name.givenName,emails.type");

        // 'id' and 'schemas' have returned:always and cannot be excluded
        assertTrue(res.containsKey("id"));
        assertTrue(res.containsKey("schemas"));
        assertFalse(res.containsKey("password"));

        Map<String, Object> name = (Map<String, Object>) res.get("name");
        assertFalse(name.containsKey("givenName"));
        assertEquals("Jensen", name.get("familyName"));

        List<Map<String, Object>> emails = (List<Map<String, Object>>) res.get("emails");
        assertFalse(emails.get(0).containsKey("type"));
        assertEquals("bjensen@example.com", emails.get(0).get("value"));
    }
}
