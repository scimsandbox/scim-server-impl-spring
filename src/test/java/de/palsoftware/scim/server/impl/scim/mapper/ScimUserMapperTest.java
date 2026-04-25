package de.palsoftware.scim.server.impl.scim.mapper;

import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.model.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class ScimUserMapperTest {

    private ScimUser user;

    @BeforeEach
    void setUp() {
        user = new ScimUser();
        user.setId(UUID.randomUUID());
        user.setUserName("testuser");
        user.setExternalId("ext-123");
        user.setActive(true);
        user.setCreatedAt(java.time.Instant.now());
        user.setLastModified(java.time.Instant.now());
        user.setVersion(1L);
        // Add name
        user.setNameFormatted("Test User");
        user.setNameFamilyName("User");
        user.setNameGivenName("Test");
        // Emails
        ScimUserEmail email = new ScimUserEmail();
        email.setValue("test@example.com");
        email.setType("work");
        email.setPrimaryFlag(true);
        user.getEmails().add(email);
        
        // Add enterprise extension
        user.setEnterpriseEmployeeNumber("12345");
        user.setEnterpriseCostCenter("CC1");
        user.setEnterpriseOrganization("Org");
        user.setEnterpriseDivision("Div");
        user.setEnterpriseDepartment("Dept");
        user.setEnterpriseManagerValue("manager-id");
        user.setEnterpriseManagerRef("../Users/manager-id");
        user.setEnterpriseManagerDisplay("Manager");
    }

    @Test
    void testToScimResponse() {
        List<Map<String, Object>> groups = List.of(Map.of("value", "group1", "display", "Group 1"));
        Map<String, Object> response = ScimUserMapper.toScimResponse(user, "http://localhost", groups);

        assertNotNull(response);
        assertEquals(user.getId().toString(), response.get("id"));
        assertEquals("testuser", response.get("userName"));
        assertEquals("ext-123", response.get("externalId"));

        assertTrue(response.containsKey("meta"));
        assertTrue(response.containsKey("groups"));

        @SuppressWarnings("unchecked")
        Map<String, Object> enterprise = (Map<String, Object>) response.get(ScimUserMapper.ENTERPRISE_SCHEMA);
        assertNotNull(enterprise);
        assertEquals("12345", enterprise.get("employeeNumber"));
        @SuppressWarnings("unchecked")
        Map<String, Object> manager = (Map<String, Object>) enterprise.get("manager");
        assertNotNull(manager);
        assertEquals("manager-id", manager.get("value"));
    }

    @Test
    void testApplyFromScimInput_Update() {
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("userName", "updateduser");
        input.put("externalId", "ext-update");
        input.put("displayName", "Updated Name");
        input.put("active", false);

        Map<String, Object> name = new LinkedHashMap<>();
        name.put("formatted", "Updated Name");
        name.put("familyName", "Name");
        name.put("givenName", "Updated");
        input.put("name", name);

        Map<String, Object> enterpriseMap = new LinkedHashMap<>();
        enterpriseMap.put("employeeNumber", "999");
        enterpriseMap.put("costCenter", "CC2");
        Map<String, Object> manager = new LinkedHashMap<>();
        manager.put("value", "manager-999");
        manager.put("$ref", "../Users/manager-999");
        manager.put("displayName", "Manager 999");
        enterpriseMap.put("manager", manager);
        input.put(ScimUserMapper.ENTERPRISE_SCHEMA, enterpriseMap);

        ScimUser userToUpdate = new ScimUser();
        ScimUserMapper.applyFromScimInput(userToUpdate, input);

        assertEquals("updateduser", userToUpdate.getUserName());
        assertEquals("ext-update", userToUpdate.getExternalId());
        assertEquals("Updated Name", userToUpdate.getDisplayName());
        assertFalse(userToUpdate.isActive());
        assertEquals("Updated Name", userToUpdate.getNameFormatted());
        assertEquals("999", userToUpdate.getEnterpriseEmployeeNumber());
        assertEquals("manager-999", userToUpdate.getEnterpriseManagerValue());
    }

    @Test
    void testClearMutableAttributes() {
        ScimUserMapper.clearMutableAttributes(user);

        assertNull(user.getExternalId());
        assertNull(user.getNameFormatted());
        assertNull(user.getDisplayName());
        assertTrue(user.isActive());
        assertTrue(user.getEmails().isEmpty());
        assertNull(user.getEnterpriseEmployeeNumber());
    }

    @Test
    void testToCollectionMappersAndValidators() {
        Map<String, Object> item = new HashMap<>();
        item.put("value", "test@test.com");
        item.put("type", "work");
        ScimUserEmail email = ScimUserMapper.buildEmail(item);
        assertEquals("test@test.com", email.getValue());
        assertEquals("work", email.getType());

        item.put("type", "invalid");
        assertThrows(ScimException.class, () -> ScimUserMapper.buildEmail(item));

        item.clear();
        item.put("value", Base64.getEncoder().encodeToString("cert".getBytes()));
        item.put("type", "work");
        ScimUserX509Certificate cert = ScimUserMapper.buildCertificate(item);
        assertNotNull(cert.getValue());

        item.put("value", "invalid-base64!!");
        assertThrows(ScimException.class, () -> ScimUserMapper.buildCertificate(item));
    }
}
