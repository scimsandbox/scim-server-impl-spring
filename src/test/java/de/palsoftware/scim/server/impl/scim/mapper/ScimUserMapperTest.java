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

        // RFC 7643 §7: canonicalValues on 'type' are advisory; custom string types are accepted
        item.put("type", "invalid");
        ScimUserEmail customTypeEmail = ScimUserMapper.buildEmail(item);
        assertEquals("invalid", customTypeEmail.getType());

        // Non-string type must still fail with 400 invalidValue
        item.put("type", 123);
        assertThrows(ScimException.class, () -> ScimUserMapper.buildEmail(item));

        // Omitted emails.type defaults to "work" per RFC 7643 §2.4 / §4.1.2
        Map<String, Object> defaultTypeEmailMap = new HashMap<>();
        defaultTypeEmailMap.put("value", "Alice@EXAMPLE.COM");
        ScimUserEmail defaultTypeEmail = ScimUserMapper.buildEmail(defaultTypeEmailMap);
        assertEquals("Alice@example.com", defaultTypeEmail.getValue());
        assertEquals("work", defaultTypeEmail.getType());

        item.clear();
        item.put("value", Base64.getEncoder().encodeToString("cert".getBytes()));
        item.put("type", "work");
        ScimUserX509Certificate cert = ScimUserMapper.buildCertificate(item);
        assertNotNull(cert.getValue());

        item.put("value", "invalid-base64!!");
        assertThrows(ScimException.class, () -> ScimUserMapper.buildCertificate(item));
    }

    @Test
    void testPasswordHashingOnCreateAndUpdate() {
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("userName", "hashedUser");
        input.put("password", "PlaintextPassword!123");

        ScimUser newUser = new ScimUser();
        ScimUserMapper.applyFromScimInput(newUser, input);
        assertNotNull(newUser.getPassword());
        assertTrue(newUser.getPassword().startsWith("$2a$") || newUser.getPassword().startsWith("$2b$"));
        assertTrue(new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().matches("PlaintextPassword!123", newUser.getPassword()));

        // When password is already bcrypt-hashed, it should not be rehashed
        String preHashed = "$2a$10$abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqr";
        input.put("password", preHashed);
        ScimUserMapper.applyFromScimInput(newUser, input);
        assertEquals(preHashed, newUser.getPassword());

        // When password is null or empty
        input.put("password", null);
        ScimUserMapper.applyFromScimInput(newUser, input);
        assertNull(newUser.getPassword());

        // Exactly 72 UTF-8 bytes succeeds
        String exact72Ascii = "a".repeat(72);
        input.put("password", exact72Ascii);
        ScimUserMapper.applyFromScimInput(newUser, input);
        assertNotNull(newUser.getPassword());
        assertTrue(new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().matches(exact72Ascii, newUser.getPassword()));

        // 73 ASCII bytes rejected with 400 invalidValue (not 500 IllegalArgumentException)
        input.put("password", "a".repeat(73));
        ScimException asciiEx = assertThrows(ScimException.class, () -> ScimUserMapper.applyFromScimInput(newUser, input));
        assertEquals(400, asciiEx.getHttpStatus());
        assertEquals("invalidValue", asciiEx.getScimType());

        // 25x 3-byte UTF-8 characters ('€') = 25 chars but 75 UTF-8 bytes -> rejected with 400 invalidValue
        input.put("password", "€".repeat(25));
        ScimException utf8Ex = assertThrows(ScimException.class, () -> ScimUserMapper.applyFromScimInput(newUser, input));
        assertEquals(400, utf8Ex.getHttpStatus());
        assertEquals("invalidValue", utf8Ex.getScimType());
    }

    @Test
    void testReplaceCollection_emailDeduplicationPreservesPrimaryFlag() {
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("userName", "dedupUser");
        input.put("emails", List.of(
                Map.of("value", "dup@example.com", "type", "work", "primary", false),
                Map.of("value", "DUP@EXAMPLE.COM", "type", "WORK", "primary", true)
        ));

        ScimUser targetUser = new ScimUser();
        ScimUserMapper.applyFromScimInput(targetUser, input);

        assertEquals(1, targetUser.getEmails().size());
        assertEquals("dup@example.com", targetUser.getEmails().get(0).getValue());
        assertTrue(targetUser.getEmails().get(0).isPrimaryFlag());
    }

    @Test
    void testReplaceCollection_caseSensitiveForCertificatesAndPhotos() {
        // Base64 strings that are both valid base64 ("test" = "dGVzdA==" and "\u0074\u0065..." vs "TGVzdA==" = "Lest")
        String cert1 = Base64.getEncoder().encodeToString("test".getBytes()); // dGVzdA==
        String cert2 = "DGVzdA=="; // valid base64 differing only in first character case ('d' vs 'D')

        Map<String, Object> input = new LinkedHashMap<>();
        input.put("userName", "certUser");
        input.put("x509Certificates", List.of(
                Map.of("value", cert1, "type", "work", "primary", false),
                Map.of("value", cert2, "type", "work", "primary", true)
        ));
        input.put("photos", List.of(
                Map.of("value", "https://example.com/PhotoA.png", "type", "photo", "primary", false),
                Map.of("value", "https://example.com/photoa.png", "type", "photo", "primary", true)
        ));

        ScimUser targetUser = new ScimUser();
        ScimUserMapper.applyFromScimInput(targetUser, input);

        assertEquals(2, targetUser.getX509Certificates().size());
        assertEquals(cert1, targetUser.getX509Certificates().get(0).getValue());
        assertEquals(cert2, targetUser.getX509Certificates().get(1).getValue());
        assertFalse(targetUser.getX509Certificates().get(0).isPrimaryFlag());
        assertTrue(targetUser.getX509Certificates().get(1).isPrimaryFlag());

        assertEquals(2, targetUser.getPhotos().size());
    }

    @Test
    void testMultiValuedPojos_equalsAndHashCode() {
        ScimUserAddress a1 = new ScimUserAddress();
        a1.setFormatted("123 Main");
        a1.setStreetAddress("123 Main");
        a1.setLocality("NYC");
        a1.setRegion("NY");
        a1.setPostalCode("10001");
        a1.setCountry("US");
        a1.setType("work");
        a1.setPrimaryFlag(true);
        ScimUserAddress a2 = new ScimUserAddress();
        a2.setFormatted("123 Main");
        a2.setStreetAddress("123 Main");
        a2.setLocality("NYC");
        a2.setRegion("NY");
        a2.setPostalCode("10001");
        a2.setCountry("US");
        a2.setType("work");
        a2.setPrimaryFlag(true);
        assertEquals(a1, a2);
        assertEquals(a1.hashCode(), a2.hashCode());
        a2.setPrimaryFlag(false);
        assertNotEquals(a1, a2);

        ScimUserEmail e1 = ScimUserMapper.buildEmail(Map.of("value", "a@b.com", "type", "work", "display", "A", "primary", true));
        ScimUserEmail e2 = ScimUserMapper.buildEmail(Map.of("value", "a@b.com", "type", "work", "display", "A", "primary", true));
        assertEquals(e1, e2);
        assertEquals(e1.hashCode(), e2.hashCode());

        ScimUserPhoneNumber p1 = ScimUserMapper.buildPhone(Map.of("value", "123", "type", "work", "display", "P", "primary", true));
        ScimUserPhoneNumber p2 = ScimUserMapper.buildPhone(Map.of("value", "123", "type", "work", "display", "P", "primary", true));
        assertEquals(p1, p2);
        assertEquals(p1.hashCode(), p2.hashCode());

        ScimUserIm im1 = ScimUserMapper.buildIm(Map.of("value", "im1", "type", "xmpp", "display", "IM", "primary", false));
        ScimUserIm im2 = ScimUserMapper.buildIm(Map.of("value", "im1", "type", "xmpp", "display", "IM", "primary", false));
        assertEquals(im1, im2);
        assertEquals(im1.hashCode(), im2.hashCode());

        ScimUserPhoto ph1 = ScimUserMapper.buildPhoto(Map.of("value", "https://example.com/p.png", "type", "photo", "display", "Ph", "primary", false));
        ScimUserPhoto ph2 = ScimUserMapper.buildPhoto(Map.of("value", "https://example.com/p.png", "type", "photo", "display", "Ph", "primary", false));
        assertEquals(ph1, ph2);
        assertEquals(ph1.hashCode(), ph2.hashCode());

        ScimUserEntitlement ent1 = ScimUserMapper.buildEntitlement(Map.of("value", "ent", "type", "t", "display", "E", "primary", false));
        ScimUserEntitlement ent2 = ScimUserMapper.buildEntitlement(Map.of("value", "ent", "type", "t", "display", "E", "primary", false));
        assertEquals(ent1, ent2);
        assertEquals(ent1.hashCode(), ent2.hashCode());

        ScimUserRole r1 = ScimUserMapper.buildRole(Map.of("value", "admin", "type", "t", "display", "R", "primary", true));
        ScimUserRole r2 = ScimUserMapper.buildRole(Map.of("value", "admin", "type", "t", "display", "R", "primary", true));
        assertEquals(r1, r2);
        assertEquals(r1.hashCode(), r2.hashCode());

        ScimUserX509Certificate c1 = ScimUserMapper.buildCertificate(Map.of("value", "dGVzdA==", "type", "work", "display", "C", "primary", false));
        ScimUserX509Certificate c2 = ScimUserMapper.buildCertificate(Map.of("value", "dGVzdA==", "type", "work", "display", "C", "primary", false));
        assertEquals(c1, c2);
        assertEquals(c1.hashCode(), c2.hashCode());
    }

    @Test
    @SuppressWarnings("unchecked")
    void testMapperTimestampParity_versionZeroAndPositive() {
        java.time.Instant created = java.time.Instant.parse("2026-01-01T00:00:00Z");
        java.time.Instant modified = java.time.Instant.parse("2026-01-02T00:00:00Z");

        ScimUser u = new ScimUser();
        u.setId(UUID.randomUUID());
        u.setUserName("tsUser");
        u.setCreatedAt(created);
        u.setLastModified(modified);
        u.setVersion(0L);

        Map<String, Object> respV0 = ScimUserMapper.toScimResponse(u, "http://localhost", Collections.emptyList());
        Map<String, Object> metaV0 = (Map<String, Object>) respV0.get("meta");
        assertEquals(created.toString(), metaV0.get("created"));
        assertEquals(created.toString(), metaV0.get("lastModified"));

        u.setVersion(1L);
        Map<String, Object> respV1 = ScimUserMapper.toScimResponse(u, "http://localhost", Collections.emptyList());
        Map<String, Object> metaV1 = (Map<String, Object>) respV1.get("meta");
        assertEquals(created.toString(), metaV1.get("created"));
        assertEquals(modified.toString(), metaV1.get("lastModified"));

        ScimGroup g = new ScimGroup();
        g.setId(UUID.randomUUID());
        g.setDisplayName("tsGroup");
        g.setCreatedAt(created);
        g.setLastModified(modified);
        g.setVersion(0L);

        Map<String, Object> grpV0 = ScimGroupMapper.toScimResponse(g, "http://localhost");
        Map<String, Object> grpMetaV0 = (Map<String, Object>) grpV0.get("meta");
        assertEquals(created.toString(), grpMetaV0.get("created"));
        assertEquals(created.toString(), grpMetaV0.get("lastModified"));

        g.setVersion(2L);
        Map<String, Object> grpV2 = ScimGroupMapper.toScimResponse(g, "http://localhost");
        Map<String, Object> grpMetaV2 = (Map<String, Object>) grpV2.get("meta");
        assertEquals(created.toString(), grpMetaV2.get("created"));
        assertEquals(modified.toString(), grpMetaV2.get("lastModified"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testMicrosecondTimestampTruncation_matchesPostgresTimestamptzPrecision() {
        java.time.Instant nanoCreated = java.time.Instant.parse("2026-11-03T08:57:34.851123671Z");
        java.time.Instant nanoModified = java.time.Instant.parse("2026-11-03T09:12:45.999888777Z");
        String expectedCreatedStr = "2026-11-03T08:57:34.851123Z";
        String expectedModifiedStr = "2026-11-03T09:12:45.999888Z";

        // 1. ScimUser & ScimGroup setters + SCIM meta serialization parity
        ScimUser u = new ScimUser();
        u.setId(UUID.randomUUID());
        u.setUserName("nanoUser");
        u.setCreatedAt(nanoCreated);
        u.setLastModified(nanoModified);
        u.setVersion(1L);

        assertEquals(0, u.getCreatedAt().getNano() % 1_000);
        assertEquals(0, u.getLastModified().getNano() % 1_000);
        Map<String, Object> userMeta = (Map<String, Object>)
                ScimUserMapper.toScimResponse(u, "http://localhost", Collections.emptyList()).get("meta");
        assertEquals(expectedCreatedStr, userMeta.get("created"));
        assertEquals(expectedModifiedStr, userMeta.get("lastModified"));

        ScimGroup g = new ScimGroup();
        g.setId(UUID.randomUUID());
        g.setDisplayName("nanoGroup");
        g.setCreatedAt(nanoCreated);
        g.setLastModified(nanoModified);
        g.setVersion(1L);

        assertEquals(0, g.getCreatedAt().getNano() % 1_000);
        assertEquals(0, g.getLastModified().getNano() % 1_000);
        Map<String, Object> groupMeta = (Map<String, Object>)
                ScimGroupMapper.toScimResponse(g, "http://localhost").get("meta");
        assertEquals(expectedCreatedStr, groupMeta.get("created"));
        assertEquals(expectedModifiedStr, groupMeta.get("lastModified"));

        // 2. Lifecycle hooks (@PrePersist / @PreUpdate) across all persisted entities
        var lifecycleUser = new ScimUser() {
            void create() { onCreate(); }
            void update() { onUpdate(); }
        };
        lifecycleUser.create();
        assertEquals(lifecycleUser.getCreatedAt(), lifecycleUser.getLastModified());
        assertEquals(0, lifecycleUser.getCreatedAt().getNano() % 1_000);
        lifecycleUser.update();
        assertEquals(0, lifecycleUser.getLastModified().getNano() % 1_000);

        var lifecycleGroup = new ScimGroup() {
            void create() { onCreate(); }
            void update() { onUpdate(); }
        };
        lifecycleGroup.create();
        assertEquals(lifecycleGroup.getCreatedAt(), lifecycleGroup.getLastModified());
        assertEquals(0, lifecycleGroup.getCreatedAt().getNano() % 1_000);
        lifecycleGroup.update();
        assertEquals(0, lifecycleGroup.getLastModified().getNano() % 1_000);

        var asyncEvent = new de.palsoftware.scim.server.impl.entity.ScimAsyncEvent() {
            void create() { onCreate(); }
        };
        asyncEvent.setCreatedAt(nanoCreated);
        asyncEvent.setCompletedAt(nanoModified);
        assertEquals(expectedCreatedStr, asyncEvent.getCreatedAt().toString());
        assertEquals(expectedModifiedStr, asyncEvent.getCompletedAt().toString());
        asyncEvent.setCreatedAt(null);
        asyncEvent.create();
        assertEquals(0, asyncEvent.getCreatedAt().getNano() % 1_000);

        var ws = new Workspace() {
            void create() { onCreate(); }
            void update() { onUpdate(); }
        };
        ws.setCreatedAt(nanoCreated);
        ws.setUpdatedAt(nanoModified);
        assertEquals(expectedCreatedStr, ws.getCreatedAt().toString());
        assertEquals(expectedModifiedStr, ws.getUpdatedAt().toString());
        ws.create();
        assertEquals(0, ws.getCreatedAt().getNano() % 1_000);
        ws.update();
        assertEquals(0, ws.getUpdatedAt().getNano() % 1_000);

        var token = new WorkspaceToken() {
            void create() { onCreate(); }
            void update() { onUpdate(); }
        };
        token.setExpiresAt(nanoCreated);
        assertEquals(expectedCreatedStr, token.getExpiresAt().toString());
        token.create();
        assertEquals(0, token.getCreatedAt().getNano() % 1_000);
        token.update();
        assertEquals(0, token.getUpdatedAt().getNano() % 1_000);

        var reqLog = new ScimRequestLog() {
            void create() { onCreate(); }
        };
        reqLog.setCreatedAt(nanoCreated);
        assertEquals(expectedCreatedStr, reqLog.getCreatedAt().toString());
        reqLog.create();
        assertEquals(0, reqLog.getCreatedAt().getNano() % 1_000);
    }

    @Test
    // RFC7643-2.4-63934b
    void applyEnterpriseManager_supportsRefOnlyClearsStaleRefAndRejectsConflicts() {
        ScimUser user = new ScimUser();
        UUID mgr1 = UUID.randomUUID();
        UUID mgr2 = UUID.randomUUID();

        // $ref-only manager populates enterpriseManagerValue and enterpriseManagerRef
        ScimUserMapper.applyEnterpriseManager(user, Map.of(
                "$ref", "https://legacy.example/scim/v1/Users/" + mgr1.toString().toUpperCase()));
        assertEquals(mgr1.toString(), user.getEnterpriseManagerValue());
        assertNotNull(user.getEnterpriseManagerRef());

        // String manager clears stale enterpriseManagerRef
        ScimUserMapper.applyEnterpriseManager(user, mgr2.toString());
        assertEquals(mgr2.toString(), user.getEnterpriseManagerValue());
        assertNull(user.getEnterpriseManagerRef());

        // Conflicting value vs $ref, non-SCIM URI, and /Groups/<id> URI all fail with 400 invalidValue
        ScimException conflict = assertThrows(ScimException.class, () ->
                ScimUserMapper.applyEnterpriseManager(user, Map.of(
                        "value", mgr1.toString(),
                        "$ref", "/Users/" + mgr2)));
        assertEquals(400, conflict.getHttpStatus());
        assertEquals("invalidValue", conflict.getScimType());

        ScimException nonScim = assertThrows(ScimException.class, () ->
                ScimUserMapper.applyEnterpriseManager(user, Map.of(
                        "$ref", "https://example.com/OtherPath/123")));
        assertEquals(400, nonScim.getHttpStatus());
        assertEquals("invalidValue", nonScim.getScimType());

        ScimException wrongType = assertThrows(ScimException.class, () ->
                ScimUserMapper.applyEnterpriseManager(user, Map.of(
                        "$ref", "/Groups/" + mgr1)));
        assertEquals(400, wrongType.getHttpStatus());
        assertEquals("invalidValue", wrongType.getScimType());
    }
}
