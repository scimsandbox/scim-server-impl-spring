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
        assertNotNull(user.getPassword());
        assertTrue(user.getPassword().startsWith("$2a$") || user.getPassword().startsWith("$2b$"));
        assertTrue(new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().matches("secret", user.getPassword()));
    }

    @Test
    void testPatchAlreadyHashedPasswordNotRehashed() {
        String preHashed = "$2a$10$abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqr";
        List<Map<String, Object>> ops = List.of(
            Map.of("op", "replace", "path", "password", "value", preHashed)
        );
        ScimPatchEngine.applyPatchOperations(user, ops);
        assertEquals(preHashed, user.getPassword());
    }

    @Test
    void testPatchPasswordViaValueMapWithoutPath() {
        Map<String, Object> value = Map.of("password", "newSecret123");
        List<Map<String, Object>> ops = List.of(
            Map.of("op", "replace", "value", value)
        );
        ScimPatchEngine.applyPatchOperations(user, ops);
        assertNotNull(user.getPassword());
        assertTrue(new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().matches("newSecret123", user.getPassword()));
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
        // RFC 7643 §4.3: manager.displayName is readOnly and ignored from client input (resolved by ScimUserService)
        assertNull(user.getEnterpriseManagerDisplay());

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
        assertEquals("US", user.getAddresses().get(0).getCountry());
        
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

    @Test
    void testAddOperation_missingValue_throws400() {
        // PAT_24: RFC 7644 §3.5.2.1 - The 'add' operation MUST contain a 'value' member
        List<Map<String, Object>> opsWithoutValue = List.of(Map.of("op", "add", "path", "title"));
        ScimException ex = assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, opsWithoutValue));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidValue", ex.getScimType());

        Map<String, Object> opWithNullValue = new HashMap<>();
        opWithNullValue.put("op", "add");
        opWithNullValue.put("path", "title");
        opWithNullValue.put("value", null);
        ScimException exNull = assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, List.of(opWithNullValue)));
        assertEquals(400, exNull.getHttpStatus());
        assertEquals("invalidValue", exNull.getScimType());
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
        
        // RFC 7643 §7: canonicalValues on 'type' are advisory; custom string types are accepted
        List<Map<String, Object>> ops = List.of(
            Map.of("op", "replace", "path", "emails[type eq \"work\"].type", "value", "invalid_type")
        );
        ScimPatchEngine.applyPatchOperations(user, ops);
        assertEquals("invalid_type", email.getType());

        // Non-string type must fail with 400 invalidValue
        List<Map<String, Object>> opsNonStringType = List.of(
            Map.of("op", "replace", "path", "emails[type eq \"invalid_type\"].type", "value", 123)
        );
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, opsNonStringType));
        
        // Invalid cert
        ScimUserX509Certificate cert = new ScimUserX509Certificate();
        cert.setValue("abc");
        user.getX509Certificates().add(cert);
        
        List<Map<String, Object>> opsCert = List.of(
            Map.of("op", "replace", "path", "x509Certificates[value eq \"abc\"].value", "value", "invalid base64!")
        );
        assertThrows(ScimException.class, () -> ScimPatchEngine.applyPatchOperations(user, opsCert));
    }

    @Test
    void testReplaceNameNoPathAndWithPath() {
        // Replace without path (RFC 7644)
        Map<String, Object> nameMap = new LinkedHashMap<>();
        nameMap.put("familyName", "Jensen");
        nameMap.put("givenName", "Barbara");
        List<Map<String, Object>> ops = List.of(
            Map.of("op", "replace", "value", Map.of("name", nameMap))
        );
        ScimPatchEngine.applyPatchOperations(user, ops);
        assertEquals("Jensen", user.getNameFamilyName());
        assertEquals("Barbara", user.getNameGivenName());

        // Replace with path "name"
        Map<String, Object> nameMap2 = new LinkedHashMap<>();
        nameMap2.put("familyName", "Doe");
        List<Map<String, Object>> ops2 = List.of(
            Map.of("op", "replace", "path", "name", "value", nameMap2)
        );
        ScimPatchEngine.applyPatchOperations(user, ops2);
        assertEquals("Doe", user.getNameFamilyName());
        assertEquals("Barbara", user.getNameGivenName()); // preserved

        // Replace with URN prefix
        Map<String, Object> nameMap3 = new LinkedHashMap<>();
        nameMap3.put("familyName", "Smith");
        List<Map<String, Object>> ops3 = List.of(
            Map.of("op", "replace", "path", "urn:ietf:params:scim:schemas:core:2.0:User:name", "value", nameMap3)
        );
        ScimPatchEngine.applyPatchOperations(user, ops3);
        assertEquals("Smith", user.getNameFamilyName());

        // Remove name
        List<Map<String, Object>> opsRemove = List.of(
            Map.of("op", "remove", "path", "name")
        );
        ScimPatchEngine.applyPatchOperations(user, opsRemove);
        assertNull(user.getNameFamilyName());
        assertNull(user.getNameGivenName());
    }

    @Test
    void testPat27_filteredReplacePrimary_unsetsExistingPrimary() {
        ScimUserEmail workEmail = new ScimUserEmail();
        workEmail.setValue("work@example.com");
        workEmail.setType("work");
        workEmail.setPrimaryFlag(true);

        ScimUserEmail homeEmail = new ScimUserEmail();
        homeEmail.setValue("home@example.com");
        homeEmail.setType("home");
        homeEmail.setPrimaryFlag(false);

        user.getEmails().add(workEmail);
        user.getEmails().add(homeEmail);

        List<Map<String, Object>> ops = List.of(
            Map.of("op", "replace", "path", "emails[type eq \"home\"].primary", "value", true)
        );
        ScimPatchEngine.applyPatchOperations(user, ops);

        assertFalse(workEmail.isPrimaryFlag());
        assertTrue(homeEmail.isPrimaryFlag());
        assertEquals(1, user.getEmails().stream().filter(ScimUserEmail::isPrimaryFlag).count());

        // Filtered replace with Map value (no subAttr) setting primary: true on work
        List<Map<String, Object>> mapReplaceOps = List.of(
            Map.of("op", "replace", "path", "emails[type eq \"work\"]",
                   "value", Map.of("value", "work2@example.com", "type", "work", "primary", true))
        );
        ScimPatchEngine.applyPatchOperations(user, mapReplaceOps);

        assertEquals("work2@example.com", user.getEmails().get(0).getValue());
        assertTrue(user.getEmails().get(0).isPrimaryFlag());
        assertFalse(user.getEmails().get(1).isPrimaryFlag());
        assertEquals(1, user.getEmails().stream().filter(ScimUserEmail::isPrimaryFlag).count());
    }

    @Test
    void testPat27_addAndReplaceMultiValued_normalizesSinglePrimary() {
        ScimUserEmail existing = new ScimUserEmail();
        existing.setValue("first@example.com");
        existing.setType("work");
        existing.setPrimaryFlag(true);
        user.getEmails().add(existing);

        // PATCH add with primary: true should unset existing primary
        List<Map<String, Object>> addOps = List.of(
            Map.of("op", "add", "path", "emails",
                   "value", List.of(Map.of("value", "second@example.com", "type", "home", "primary", true)))
        );
        ScimPatchEngine.applyPatchOperations(user, addOps);

        assertEquals(2, user.getEmails().size());
        assertFalse(user.getEmails().get(0).isPrimaryFlag());
        assertTrue(user.getEmails().get(1).isPrimaryFlag());

        // Whole-array PATCH replace with multiple primary: true entries keeps at most one primary
        List<Map<String, Object>> replaceOps = List.of(
            Map.of("op", "replace", "path", "emails", "value", List.of(
                Map.of("value", "a@example.com", "type", "work", "primary", true),
                Map.of("value", "b@example.com", "type", "home", "primary", true)
            ))
        );
        ScimPatchEngine.applyPatchOperations(user, replaceOps);

        assertEquals(2, user.getEmails().size());
        assertEquals(1, user.getEmails().stream().filter(ScimUserEmail::isPrimaryFlag).count());
        assertFalse(user.getEmails().get(0).isPrimaryFlag());
        assertTrue(user.getEmails().get(1).isPrimaryFlag());
    }

    @Test
    void testAddEmails_deduplicatesCaseInsensitivelyAndMergesPrimary() {
        ScimUserEmail existingWork = new ScimUserEmail();
        existingWork.setValue("dup@example.com");
        existingWork.setType("work");
        existingWork.setPrimaryFlag(false);

        ScimUserEmail existingHome = new ScimUserEmail();
        existingHome.setValue("home@example.com");
        existingHome.setType("home");
        existingHome.setPrimaryFlag(true);

        user.getEmails().add(existingWork);
        user.getEmails().add(existingHome);

        List<Map<String, Object>> ops = List.of(
            Map.of("op", "add", "path", "emails",
                   "value", List.of(Map.of("value", "DUP@EXAMPLE.COM", "type", "WORK", "primary", true)))
        );
        ScimPatchEngine.applyPatchOperations(user, ops);

        assertEquals(2, user.getEmails().size());
        assertTrue(user.getEmails().get(0).isPrimaryFlag());
        assertFalse(user.getEmails().get(1).isPrimaryFlag());
    }

    @Test
    void testFilteredPatch_caseExactPhotosAndCertificates() {
        ScimUserX509Certificate cert = new ScimUserX509Certificate();
        cert.setValue("QUJD");
        cert.setDisplay("OldCert");
        user.getX509Certificates().add(cert);

        ScimUserPhoto photo = new ScimUserPhoto();
        photo.setValue("https://example.com/Photos/UserPic.png");
        photo.setType("photo");
        user.getPhotos().add(photo);

        // Wrong casing on caseExact=true x509Certificates.value must NOT match (400 noTarget on replace, no-op on remove)
        ScimException certReplaceMismatch = assertThrows(ScimException.class, () ->
                ScimPatchEngine.applyPatchOperations(user, List.of(
                        Map.of("op", "replace", "path", "x509Certificates[value eq \"qujd\"].display", "value", "WrongCase"))));
        assertEquals(400, certReplaceMismatch.getHttpStatus());
        assertEquals("noTarget", certReplaceMismatch.getScimType());

        ScimPatchEngine.applyPatchOperations(user, List.of(
                Map.of("op", "remove", "path", "x509Certificates[value eq \"qujd\"]")));
        assertEquals(1, user.getX509Certificates().size());

        // Exact casing on x509Certificates.value and photos.value matches
        ScimPatchEngine.applyPatchOperations(user, List.of(
                Map.of("op", "replace", "path", "x509Certificates[value eq \"QUJD\"].display", "value", "ExactCert")));
        assertEquals("ExactCert", user.getX509Certificates().get(0).getDisplay());

        ScimException photoReplaceMismatch = assertThrows(ScimException.class, () ->
                ScimPatchEngine.applyPatchOperations(user, List.of(
                        Map.of("op", "replace", "path", "photos[value eq \"https://example.com/photos/userpic.png\"].display", "value", "Wrong"))));
        assertEquals("noTarget", photoReplaceMismatch.getScimType());

        ScimPatchEngine.applyPatchOperations(user, List.of(
                Map.of("op", "remove", "path", "photos[value eq \"https://example.com/Photos/UserPic.png\"]")));
        assertTrue(user.getPhotos().isEmpty());
    }

    @Test
    void testFilteredPatch_addressSubAttributesAndCompoundFilterExpressions() {
        ScimUserAddress workBerlin = new ScimUserAddress();
        workBerlin.setType("work");
        workBerlin.setLocality("Berlin");
        workBerlin.setStreetAddress("Unter den Linden 1");

        ScimUserAddress workMunich = new ScimUserAddress();
        workMunich.setType("work");
        workMunich.setLocality("Munich");
        workMunich.setStreetAddress("Marienplatz 1");

        user.getAddresses().add(workBerlin);
        user.getAddresses().add(workMunich);

        // Compound filter on addresses.locality + type
        ScimPatchEngine.applyPatchOperations(user, List.of(
                Map.of("op", "replace", "path", "addresses[locality eq \"Berlin\" and type eq \"work\"].postalCode", "value", "10117")));
        assertEquals("10117", workBerlin.getPostalCode());
        assertNull(workMunich.getPostalCode());

        // Non-eq operator (sw) + pr in filtered remove
        ScimPatchEngine.applyPatchOperations(user, List.of(
                Map.of("op", "remove", "path", "addresses[streetAddress sw \"Marien\" and locality pr]")));
        assertEquals(1, user.getAddresses().size());
        assertEquals("Berlin", user.getAddresses().get(0).getLocality());
    }

    @Test
    void testFilteredPatch_malformedFilterAndUnbalancedBrackets_throwScimErrorEvenOnEmptyRemove() {
        // user.getEmails() is empty: op=remove with invalid filter syntax MUST still fail with 400 invalidFilter
        for (String badFilterPath : List.of(
                "emails[type eq]",
                "emails[type eq\"work\"]",
                "emails[unknownSub eq \"x\"]",
                "emails[]")) {
            ScimException ex = assertThrows(ScimException.class, () ->
                    ScimPatchEngine.applyPatchOperations(user, List.of(
                            Map.of("op", "remove", "path", badFilterPath))),
                    "Expected 400 invalidFilter for path: " + badFilterPath);
            assertEquals(400, ex.getHttpStatus());
            assertEquals("invalidFilter", ex.getScimType());
        }

        // Unbalanced brackets in add, replace, and remove MUST fail with 400 invalidPath
        for (String unbalanced : List.of("emails[type eq \"work\"", "emails]")) {
            ScimException addEx = assertThrows(ScimException.class, () ->
                    ScimPatchEngine.applyPatchOperations(user, List.of(
                            Map.of("op", "add", "path", unbalanced, "value", "x"))));
            assertEquals(400, addEx.getHttpStatus());
            assertEquals("invalidPath", addEx.getScimType());

            ScimException repEx = assertThrows(ScimException.class, () ->
                    ScimPatchEngine.applyPatchOperations(user, List.of(
                            Map.of("op", "replace", "path", unbalanced, "value", "x"))));
            assertEquals(400, repEx.getHttpStatus());
            assertEquals("invalidPath", repEx.getScimType());

            ScimException remEx = assertThrows(ScimException.class, () ->
                    ScimPatchEngine.applyPatchOperations(user, List.of(
                            Map.of("op", "remove", "path", unbalanced))));
            assertEquals(400, remEx.getHttpStatus());
            assertEquals("invalidPath", remEx.getScimType());
        }
    }

    @Test
    // RFC7643-2.4-63934b
    void testEnterpriseManagerPatch_refOnlyNoStaleRefAndPathlessConflictRejection() {
        String ent = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
        UUID mgr1 = UUID.randomUUID();
        UUID mgr2 = UUID.randomUUID();

        // 1. $ref-only manager object via PATCH sets enterpriseManagerValue and enterpriseManagerRef
        ScimPatchEngine.applyPatchOperations(user, List.of(Map.of(
                "op", "replace",
                "path", ent + ":manager",
                "value", Map.of("$ref", "https://legacy.example/scim/v1/Users/" + mgr1))));
        assertEquals(mgr1.toString(), user.getEnterpriseManagerValue());
        assertEquals("https://legacy.example/scim/v1/Users/" + mgr1, user.getEnterpriseManagerRef());

        // 2. Patching manager.value clears stale enterpriseManagerRef
        ScimPatchEngine.applyPatchOperations(user, List.of(Map.of(
                "op", "replace",
                "path", ent + ":manager.value",
                "value", mgr2.toString())));
        assertEquals(mgr2.toString(), user.getEnterpriseManagerValue());
        assertNull(user.getEnterpriseManagerRef());

        // 3. Patching manager.$ref updates enterpriseManagerValue to match the new User $ref
        ScimPatchEngine.applyPatchOperations(user, List.of(Map.of(
                "op", "replace",
                "path", ent + ":manager.$ref",
                "value", "../Users/" + mgr1)));
        assertEquals(mgr1.toString(), user.getEnterpriseManagerValue());
        assertEquals("../Users/" + mgr1, user.getEnterpriseManagerRef());

        // 4. Pathless PATCH with conflicting manager.value and manager.$ref fails with 400 invalidValue
        ScimException conflict = assertThrows(ScimException.class, () ->
                ScimPatchEngine.applyPatchOperations(user, List.of(Map.of(
                        "op", "replace",
                        "value", Map.of(
                                ent + ":manager.value", mgr1.toString(),
                                ent + ":manager.$ref", "/Users/" + mgr2)))));
        assertEquals(400, conflict.getHttpStatus());
        assertEquals("invalidValue", conflict.getScimType());
    }
}
