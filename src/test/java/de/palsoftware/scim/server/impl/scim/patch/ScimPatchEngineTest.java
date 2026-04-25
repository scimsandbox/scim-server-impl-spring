package de.palsoftware.scim.server.impl.scim.patch;

import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.model.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class ScimPatchEngineTest {

    private ScimUser user;

    @BeforeEach
    void setUp() {
        user = new ScimUser();
        user.setId(UUID.randomUUID());
        user.setUserName("testUser");
    }

    @Test
    void testEmptyOperations() {
        List<Map<String, Object>> emptyOperations = Collections.emptyList();

        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, null));
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, emptyOperations));
    }

    @Test
    void testReadOnlyAttributes() {
        List<Map<String, Object>> ops = List.of(Map.of("op", "replace", "path", "id", "value", "newId"));
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, ops));
    }

    @Test
    void testUnknownOperation() {
        List<Map<String, Object>> ops = List.of(Map.of("op", "unknown", "path", "userName", "value", "newId"));
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, ops));
    }

    // ── ADD TESTS ──

    @Test
    void testAddNoPath() {
        Map<String, Object> value = Map.of("userName", "newValue", "nickName", "newNick");
        List<Map<String, Object>> ops = List.of(Map.of("op", "add", "value", value));
        ScimPatchEngine.applyPatchOperations(user, ops);
        assertEquals("newValue", user.getUserName());
        assertEquals("newNick", user.getNickName());
        
        // Invalid Add no path (not a map)
        List<Map<String, Object>> opsInvalid = List.of(Map.of("op", "add", "value", "string"));
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, opsInvalid));
    }

    @Test
    void testAddSingleAttributes() {
        List<Map<String, Object>> ops = List.of(
            Map.of("op", "add", "path", "externalId", "value", "ext123"),
            Map.of("op", "add", "path", "displayName", "value", "Display Name"),
            Map.of("op", "add", "path", "nickName", "value", "Nick"),
            Map.of("op", "add", "path", "profileUrl", "value", "http://example.com"),
            Map.of("op", "add", "path", "title", "value", "Title"),
            Map.of("op", "add", "path", "userType", "value", "Employee"),
            Map.of("op", "add", "path", "preferredLanguage", "value", "en"),
            Map.of("op", "add", "path", "locale", "value", "en-US"),
            Map.of("op", "add", "path", "timezone", "value", "UTC"),
            Map.of("op", "add", "path", "active", "value", true),
            Map.of("op", "add", "path", "password", "value", "secret")
        );
        ScimPatchEngine.applyPatchOperations(user, ops);
        
        assertEquals("ext123", user.getExternalId());
        assertEquals("Display Name", user.getDisplayName());
        assertEquals("Nick", user.getNickName());
        assertEquals("http://example.com", user.getProfileUrl());
        assertEquals("Title", user.getTitle());
        assertEquals("Employee", user.getUserType());
        assertEquals("en", user.getPreferredLanguage());
        assertEquals("en-US", user.getLocale());
        assertEquals("UTC", user.getTimezone());
        assertTrue(user.isActive());
        assertEquals("secret", user.getPassword());
    }

    @Test
    void testAddSubAttributes() {
        List<Map<String, Object>> ops = List.of(
            Map.of("op", "add", "path", "name.formatted", "value", "Formatted"),
            Map.of("op", "add", "path", "name.familyName", "value", "Family"),
            Map.of("op", "add", "path", "name.givenName", "value", "Given"),
            Map.of("op", "add", "path", "name.middleName", "value", "Middle"),
            Map.of("op", "add", "path", "name.honorificPrefix", "value", "Prefix"),
            Map.of("op", "add", "path", "name.honorificSuffix", "value", "Suffix")
        );
        ScimPatchEngine.applyPatchOperations(user, ops);
        assertEquals("Formatted", user.getNameFormatted());
        assertEquals("Family", user.getNameFamilyName());
        assertEquals("Given", user.getNameGivenName());
        assertEquals("Middle", user.getNameMiddleName());
        assertEquals("Prefix", user.getNameHonorificPrefix());
        assertEquals("Suffix", user.getNameHonorificSuffix());

        List<Map<String, Object>> opsErr = List.of(Map.of("op", "add", "path", "name.unknown", "value", "Val"));
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, opsErr));
        
        List<Map<String, Object>> opsErr2 = List.of(Map.of("op", "add", "path", "unknown.sub", "value", "Val"));
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, opsErr2));
    }

    @Test
    void testAddEnterpriseAttributes() {
        String enterprisePrefix = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:";
        List<Map<String, Object>> ops = List.of(
            Map.of("op", "add", "path", enterprisePrefix + "employeeNumber", "value", "12345"),
            Map.of("op", "add", "path", enterprisePrefix + "costCenter", "value", "CC1"),
            Map.of("op", "add", "path", enterprisePrefix + "organization", "value", "Org"),
            Map.of("op", "add", "path", enterprisePrefix + "division", "value", "Div"),
            Map.of("op", "add", "path", enterprisePrefix + "department", "value", "Dept"),
            Map.of("op", "add", "path", enterprisePrefix + "manager", "value", "bob")
        );
        ScimPatchEngine.applyPatchOperations(user, ops);
        assertEquals("12345", user.getEnterpriseEmployeeNumber());
        assertEquals("CC1", user.getEnterpriseCostCenter());
        assertEquals("Org", user.getEnterpriseOrganization());
        assertEquals("Div", user.getEnterpriseDivision());
        assertEquals("Dept", user.getEnterpriseDepartment());
        assertEquals("bob", user.getEnterpriseManagerValue());

        List<Map<String, Object>> opsNullMgr = List.of(Map.of("op", "add", "path", enterprisePrefix + "manager", "value", ""));
        ScimPatchEngine.applyPatchOperations(user, opsNullMgr);
        assertNull(user.getEnterpriseManagerValue());

        Map<String, Object> mgrObj = Map.of("value", "alice", "$ref", "http://example.com/Users/alice", "displayName", "Alice");
        List<Map<String, Object>> opsObjMgr = List.of(Map.of("op", "add", "path", enterprisePrefix + "manager", "value", mgrObj));
        ScimPatchEngine.applyPatchOperations(user, opsObjMgr);
        assertEquals("alice", user.getEnterpriseManagerValue());
        assertEquals("http://example.com/Users/alice", user.getEnterpriseManagerRef());
        assertEquals("Alice", user.getEnterpriseManagerDisplay());

        List<Map<String, Object>> opsErr = List.of(Map.of("op", "add", "path", enterprisePrefix + "unknown", "value", "Val"));
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, opsErr));
        
        List<Map<String, Object>> opsErrMgr = List.of(Map.of("op", "add", "path", enterprisePrefix + "manager", "value", 123)); // invalid type for manager
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, opsErrMgr));
        
        // Invalid manager Ref
        Map<String, Object> mgrObjInvalid = Map.of("value", "alice", "$ref", "/alice", "displayName", "Alice");
        List<Map<String, Object>> opsObjMgrInvalid = List.of(Map.of("op", "add", "path", enterprisePrefix + "manager", "value", mgrObjInvalid));
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, opsObjMgrInvalid));
    }

    @Test
    void testAddMultiValuedAttributes() {
        List<Map<String, Object>> ops = List.of(
            Map.of("op", "add", "path", "emails", "value", List.of(Map.of("value", "bob@example.com", "type", "work", "primary", true))),
            Map.of("op", "add", "path", "phoneNumbers", "value", Map.of("value", "123-456", "type", "work")), // Add object instead of list
            Map.of("op", "add", "path", "addresses", "value", List.of(Map.of("type", "work", "streetAddress", "123 Main St", "postalCode", "12345", "region", "NY", "country", "USA"))),
            Map.of("op", "add", "path", "ims", "value", List.of(Map.of("value", "bob_aim", "type", "aim"))),
            Map.of("op", "add", "path", "photos", "value", List.of(Map.of("value", "http://example.com/photo.jpg", "type", "photo"))),
            Map.of("op", "add", "path", "roles", "value", List.of(Map.of("value", "Admin"))),
            Map.of("op", "add", "path", "entitlements", "value", List.of(Map.of("value", "Premium"))),
            Map.of("op", "add", "path", "x509Certificates", "value", List.of(Map.of("value", "dGVzdA==")))
        );
        ScimPatchEngine.applyPatchOperations(user, ops);

        assertEquals(1, user.getEmails().size());
        assertEquals("bob@example.com", user.getEmails().get(0).getValue());
        
        assertEquals(1, user.getPhoneNumbers().size());
        assertEquals("123-456", user.getPhoneNumbers().get(0).getValue());
        
        assertEquals(1, user.getAddresses().size());
        assertEquals("123 Main St", user.getAddresses().get(0).getStreetAddress());
        assertEquals("12345", user.getAddresses().get(0).getPostalCode());
        assertEquals("NY", user.getAddresses().get(0).getRegion());
        assertEquals("USA", user.getAddresses().get(0).getCountry());
        
        assertEquals(1, user.getIms().size());
        assertEquals("bob_aim", user.getIms().get(0).getValue());

        assertEquals(1, user.getRoles().size());
        assertEquals("Admin", user.getRoles().get(0).getValue());
        
        assertEquals(1, user.getEntitlements().size());
        assertEquals("Premium", user.getEntitlements().get(0).getValue());
        
        assertEquals(1, user.getX509Certificates().size());
        assertEquals("dGVzdA==", user.getX509Certificates().get(0).getValue());

        List<Map<String, Object>> opsErr = List.of(Map.of("op", "add", "path", "emails", "value", "NotAListOrMap"));
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, opsErr));
        
        List<Map<String, Object>> opsErr2 = List.of(Map.of("op", "add", "path", "unknownCollection", "value", List.of("123")));
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, opsErr2));
    }

    // ── REPLACE TESTS ──

    @Test
    void testReplaceNoPath() {
        Map<String, Object> value = Map.of("userName", "newValue", "nickName", "newNick");
        List<Map<String, Object>> ops = List.of(Map.of("op", "replace", "value", value));
        ScimPatchEngine.applyPatchOperations(user, ops);
        assertEquals("newValue", user.getUserName());
        assertEquals("newNick", user.getNickName());
        
        List<Map<String, Object>> opsInvalid = List.of(Map.of("op", "replace", "value", "string"));
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, opsInvalid));
    }

    @Test
    void testReplaceMultiValuedAttributes() {
        user.getEmails().add(new ScimUserEmail());
        
        List<Map<String, Object>> ops = List.of(
            Map.of("op", "replace", "path", "emails", "value", List.of(Map.of("value", "new@example.com", "type", "work")))
        );
        ScimPatchEngine.applyPatchOperations(user, ops);
        assertEquals(1, user.getEmails().size());
        assertEquals("new@example.com", user.getEmails().get(0).getValue());
    }

    // ── REMOVE TESTS ──

    @Test
    void testRemoveAttributes() {
        user.setExternalId("ext123");
        user.setDisplayName("Display");
        user.setNameFormatted("Formatted");
        user.setEnterpriseCostCenter("CC1");
        user.getEmails().add(new ScimUserEmail());
        user.getPhoneNumbers().add(new ScimUserPhoneNumber());
        user.getAddresses().add(new ScimUserAddress());
        user.getIms().add(new ScimUserIm());
        user.getPhotos().add(new ScimUserPhoto());
        user.getEntitlements().add(new ScimUserEntitlement());
        user.getRoles().add(new ScimUserRole());
        user.getX509Certificates().add(new ScimUserX509Certificate());
        user.setPreferredLanguage("en");
        user.setLocale("US");
        user.setTimezone("UTC");
        user.setProfileUrl("url");
        user.setTitle("Title");
        user.setUserType("dev");
        user.setNickName("nick");


        List<Map<String, Object>> ops = List.of(
            Map.of("op", "remove", "path", "externalId"),
            Map.of("op", "remove", "path", "displayName"),
            Map.of("op", "remove", "path", "name"),
            Map.of("op", "remove", "path", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:costCenter"),
            Map.of("op", "remove", "path", "emails"),
            Map.of("op", "remove", "path", "phoneNumbers"),
            Map.of("op", "remove", "path", "addresses"),
            Map.of("op", "remove", "path", "ims"),
            Map.of("op", "remove", "path", "photos"),
            Map.of("op", "remove", "path", "entitlements"),
            Map.of("op", "remove", "path", "roles"),
            Map.of("op", "remove", "path", "x509Certificates"),
            Map.of("op", "remove", "path", "preferredLanguage"),
            Map.of("op", "remove", "path", "locale"),
            Map.of("op", "remove", "path", "timezone"),
            Map.of("op", "remove", "path", "profileUrl"),
            Map.of("op", "remove", "path", "title"),
            Map.of("op", "remove", "path", "userType"),
            Map.of("op", "remove", "path", "nickName")
        );
        ScimPatchEngine.applyPatchOperations(user, ops);

        assertNull(user.getExternalId());
        assertNull(user.getDisplayName());
        assertNull(user.getNameFormatted());
        assertNull(user.getEnterpriseCostCenter());
        assertNull(user.getPreferredLanguage());
        assertNull(user.getLocale());
        assertNull(user.getTimezone());
        assertNull(user.getProfileUrl());
        assertNull(user.getTitle());
        assertNull(user.getUserType());
        assertNull(user.getNickName());

        assertTrue(user.getEmails().isEmpty());
        assertTrue(user.getPhoneNumbers().isEmpty());
        assertTrue(user.getAddresses().isEmpty());
        assertTrue(user.getIms().isEmpty());
        assertTrue(user.getPhotos().isEmpty());
        assertTrue(user.getEntitlements().isEmpty());
        assertTrue(user.getRoles().isEmpty());
        assertTrue(user.getX509Certificates().isEmpty());

        List<Map<String, Object>> opsErr = List.of(Map.of("op", "remove", "path", "unknownAttr"));
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, opsErr));
        
        List<Map<String, Object>> opsErrNoPath = List.of(Map.of("op", "remove"));
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, opsErrNoPath));
    }

    // ── FILTERED OPERATIONS TESTS ──

    @Test
    void testFilteredReplace() {
        ScimUserEmail email1 = new ScimUserEmail();
        email1.setValue("work@example.com");
        email1.setType("work");
        
        ScimUserEmail email2 = new ScimUserEmail();
        email2.setValue("home@example.com");
        email2.setType("home");
        
        user.getEmails().add(email1);
        user.getEmails().add(email2);

        List<Map<String, Object>> ops = List.of(
            Map.of("op", "replace", "path", "emails[type eq \"work\"].value", "value", "new_work@example.com")
        );
        ScimPatchEngine.applyPatchOperations(user, ops);

        assertEquals("new_work@example.com", email1.getValue());
        assertEquals("home@example.com", email2.getValue());
    }

    @Test
    void testFilteredRemove() {
        ScimUserEmail email1 = new ScimUserEmail();
        email1.setValue("work@example.com");
        email1.setType("work");
        
        ScimUserEmail email2 = new ScimUserEmail();
        email2.setValue("home@example.com");
        email2.setType("home");
        
        user.getEmails().add(email1);
        user.getEmails().add(email2);
        
        // Also test others
        ScimUserPhoneNumber p = new ScimUserPhoneNumber(); p.setType("work"); user.getPhoneNumbers().add(p);
        ScimUserAddress a = new ScimUserAddress(); a.setType("work"); user.getAddresses().add(a);
        ScimUserRole r = new ScimUserRole(); r.setValue("Admin"); user.getRoles().add(r);
        ScimUserEntitlement e = new ScimUserEntitlement(); e.setValue("Prem"); user.getEntitlements().add(e);
        ScimUserIm i = new ScimUserIm(); i.setType("aim"); user.getIms().add(i);
        ScimUserPhoto ph = new ScimUserPhoto(); ph.setType("photo"); user.getPhotos().add(ph);
        ScimUserX509Certificate x = new ScimUserX509Certificate(); x.setValue("abc"); user.getX509Certificates().add(x);

        List<Map<String, Object>> ops = List.of(
            Map.of("op", "remove", "path", "emails[type eq \"work\"]"),
            Map.of("op", "remove", "path", "phoneNumbers[type eq \"work\"]"),
            Map.of("op", "remove", "path", "addresses[type eq \"work\"]"),
            Map.of("op", "remove", "path", "roles[value eq \"Admin\"]"),
            Map.of("op", "remove", "path", "entitlements[value eq \"Prem\"]"),
            Map.of("op", "remove", "path", "ims[type eq \"aim\"]"),
            Map.of("op", "remove", "path", "photos[type eq \"photo\"]"),
            Map.of("op", "remove", "path", "x509Certificates[value eq \"abc\"]")
        );
        ScimPatchEngine.applyPatchOperations(user, ops);

        assertEquals(1, user.getEmails().size());
        assertEquals("home@example.com", user.getEmails().get(0).getValue());
        assertTrue(user.getPhoneNumbers().isEmpty());
        assertTrue(user.getAddresses().isEmpty());
        assertTrue(user.getRoles().isEmpty());
        assertTrue(user.getEntitlements().isEmpty());
        assertTrue(user.getIms().isEmpty());
        assertTrue(user.getPhotos().isEmpty());
        assertTrue(user.getX509Certificates().isEmpty());
        
        List<Map<String, Object>> opsErr = List.of(Map.of("op", "remove", "path", "unknown[type eq \"work\"]"));
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, opsErr));
    }

    @Test
    void testFilteredReplaceSubAttributes() {
        ScimUserEmail email = new ScimUserEmail();
        email.setType("work");
        user.getEmails().add(email);
        
        ScimUserPhoneNumber phone = new ScimUserPhoneNumber();
        phone.setType("work");
        user.getPhoneNumbers().add(phone);
        
        ScimUserAddress addr = new ScimUserAddress();
        addr.setType("work");
        user.getAddresses().add(addr);
        
        ScimUserIm im = new ScimUserIm();
        im.setType("aim");
        user.getIms().add(im);
        
        ScimUserPhoto photo = new ScimUserPhoto();
        photo.setType("photo");
        user.getPhotos().add(photo);
        
        ScimUserRole role = new ScimUserRole();
        role.setValue("Admin");
        user.getRoles().add(role);
        
        ScimUserEntitlement ent = new ScimUserEntitlement();
        ent.setValue("Prem");
        user.getEntitlements().add(ent);
        
        ScimUserX509Certificate cert = new ScimUserX509Certificate();
        cert.setValue("abc");
        user.getX509Certificates().add(cert);

        List<Map<String, Object>> ops = List.of(
            Map.of("op", "replace", "path", "emails[type eq \"work\"].display", "value", "Work Email"),
            Map.of("op", "replace", "path", "phoneNumbers[type eq \"work\"].primary", "value", true),
            Map.of("op", "replace", "path", "phoneNumbers[type eq \"work\"].display", "value", "Disp"),
            Map.of("op", "replace", "path", "addresses[type eq \"work\"].locality", "value", "City"),
            Map.of("op", "replace", "path", "addresses[type eq \"work\"].primary", "value", true),
            Map.of("op", "replace", "path", "addresses[type eq \"work\"].formatted", "value", "Formatted"),
            Map.of("op", "replace", "path", "ims[type eq \"aim\"].value", "value", "bob_aim2"),
            Map.of("op", "replace", "path", "ims[type eq \"aim\"].primary", "value", true),
            Map.of("op", "replace", "path", "ims[type eq \"aim\"].display", "value", "disp"),
            Map.of("op", "replace", "path", "photos[type eq \"photo\"].primary", "value", true),
            Map.of("op", "replace", "path", "photos[type eq \"photo\"].display", "value", "disp"),
            Map.of("op", "replace", "path", "roles[value eq \"Admin\"].display", "value", "Administrator"),
            Map.of("op", "replace", "path", "roles[value eq \"Admin\"].primary", "value", true),
            Map.of("op", "replace", "path", "entitlements[value eq \"Prem\"].type", "value", "type2"),
            Map.of("op", "replace", "path", "entitlements[value eq \"Prem\"].primary", "value", true),
            Map.of("op", "replace", "path", "entitlements[value eq \"Prem\"].display", "value", "Disp"),
            Map.of("op", "replace", "path", "x509Certificates[value eq \"abc\"].display", "value", "certDisplay"),
            Map.of("op", "replace", "path", "x509Certificates[value eq \"abc\"].primary", "value", true)
        );
        ScimPatchEngine.applyPatchOperations(user, ops);

        assertEquals("Work Email", email.getDisplay());
        assertTrue(phone.isPrimaryFlag());
        assertEquals("City", addr.getLocality());
        assertEquals("bob_aim2", im.getValue());
        assertTrue(photo.isPrimaryFlag());
        assertEquals("Administrator", role.getDisplay());
        assertEquals("type2", ent.getType());
        assertEquals("certDisplay", cert.getDisplay());
        
        // Test members error
        List<Map<String, Object>> opsMem = List.of(
            Map.of("op", "replace", "path", "members[value eq \"1\"].value", "value", "2")
        );
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, opsMem));
        
        List<Map<String, Object>> opsUnknown = List.of(
            Map.of("op", "replace", "path", "unknownAttr[value eq \"1\"].value", "value", "2")
        );
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, opsUnknown));
    }
    
    @Test
    void testFilteredMatchNotFound() {
        List<Map<String, Object>> ops = List.of(
            Map.of("op", "replace", "path", "emails[type eq \"work\"].value", "value", "new")
        );
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, ops));
    }

    @Test
    void testFilteredInvalidSyntax() {
        // eq missing space
        ScimUserEmail email = new ScimUserEmail();
        email.setType("work");
        user.getEmails().add(email);
        
        List<Map<String, Object>> ops = List.of(
            Map.of("op", "replace", "path", "emails[type eq\"work\"].value", "value", "new")
        );
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, ops));
        
        // empty filter Eq expression
        List<Map<String, Object>> ops2 = List.of(
            Map.of("op", "replace", "path", "emails[type eq].value", "value", "new")
        );
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, ops2));
    }

    @Test
    void testInvalidCanonicalValues() {
        ScimUserEmail email = new ScimUserEmail();
        email.setType("work");
        user.getEmails().add(email);
        
        List<Map<String, Object>> ops = List.of(
            Map.of("op", "replace", "path", "emails[type eq \"work\"].type", "value", "invalid_type")
        );
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, ops));
        
        // Invalid cert
        ScimUserX509Certificate cert = new ScimUserX509Certificate();
        cert.setValue("abc");
        user.getX509Certificates().add(cert);
        
        List<Map<String, Object>> opsCert = List.of(
            Map.of("op", "replace", "path", "x509Certificates[value eq \"abc\"].value", "value", "invalid base64!")
        );
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, opsCert));
    }
}
