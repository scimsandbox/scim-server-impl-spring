package de.palsoftware.scim.server.impl.scim.validation;

import de.palsoftware.scim.server.impl.scim.error.ScimException;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ScimCanonicalizerTest {

    @Test
    void testNormalizeNfc() {
        String nfd = "cafe\u0301";
        String nfc = "caf\u00e9";
        assertEquals(nfc, ScimCanonicalizer.normalizeNfc(nfd));
        assertNull(ScimCanonicalizer.normalizeNfc(null));
    }

    @Test
    void testRequireNullableString_RejectsNonStrings() {
        assertNull(ScimCanonicalizer.requireNullableString(null, "givenName"));
        assertEquals("caf\u00e9", ScimCanonicalizer.requireNullableString("cafe\u0301", "givenName"));

        ScimException mapEx = assertThrows(ScimException.class,
                () -> ScimCanonicalizer.requireNullableString(Map.of("nested", "bad"), "name.givenName"));
        assertEquals(400, mapEx.getHttpStatus());
        assertEquals("invalidValue", mapEx.getScimType());

        assertThrows(ScimException.class, () -> ScimCanonicalizer.requireNullableString(List.of("a"), "title"));
        assertThrows(ScimException.class, () -> ScimCanonicalizer.requireNullableString(123, "title"));
        assertThrows(ScimException.class, () -> ScimCanonicalizer.requireNullableString(true, "title"));
    }

    @Test
    void testRequireBoolean_StrictJsonBooleanOnly() {
        assertTrue(ScimCanonicalizer.requireBoolean(Boolean.TRUE, "active", false));
        assertFalse(ScimCanonicalizer.requireBoolean(Boolean.FALSE, "active", true));
        assertTrue(ScimCanonicalizer.requireBoolean(null, "active", true));

        ScimException strEx = assertThrows(ScimException.class,
                () -> ScimCanonicalizer.requireBoolean("not-a-boolean", "active", false));
        assertEquals(400, strEx.getHttpStatus());
        assertEquals("invalidValue", strEx.getScimType());

        assertThrows(ScimException.class, () -> ScimCanonicalizer.requireBoolean("true", "active", false));
        assertThrows(ScimException.class, () -> ScimCanonicalizer.requireBoolean(1, "active", false));
    }

    @Test
    void testCanonicalizeType_DefaultsAndCustomPreservation() {
        Set<String> canonical = Set.of("work", "home", "other");
        assertEquals("work", ScimCanonicalizer.canonicalizeType(null, canonical, "work", "emails.type"));
        assertEquals("work", ScimCanonicalizer.canonicalizeType("WORK", canonical, null, "emails.type"));
        assertEquals("custom_label", ScimCanonicalizer.canonicalizeType("custom_label", canonical, "work", "emails.type"));
    }

    @Test
    void testCanonicalizeEmail_LowercasesDomainOnly() {
        assertEquals("Alice@example.com", ScimCanonicalizer.canonicalizeEmail("  Alice@EXAMPLE.COM "));
        assertNull(ScimCanonicalizer.canonicalizeEmail(null));
    }

    @Test
    void testCanonicalizePhoneNumber_Rfc3966AndCompactE164AndLocal() {
        assertEquals("tel:+1-201-555-0123", ScimCanonicalizer.canonicalizePhoneNumber("+1 (201) 555-0123"));
        assertEquals("tel:+1-201-555-0123", ScimCanonicalizer.canonicalizePhoneNumber("TEL:+1 (201) 555.0123"));
        assertEquals("+155733333333", ScimCanonicalizer.canonicalizePhoneNumber("+155733333333"));
        assertEquals("123-456", ScimCanonicalizer.canonicalizePhoneNumber("123-456"));
    }

    @Test
    void testCanonicalizeIm_StripsWhitespaceAndLowercases() {
        assertEquals("foobar@example.com", ScimCanonicalizer.canonicalizeIm(" Foo Bar@Example.COM "));
    }

    @Test
    // RFC7643-2.4-63934b
    void testExtractCanonicalScimResourceTailAndComparableRefs() {
        String lowerUuid = "2819c223-7f76-453a-919d-413861904646";
        String upperUuid = lowerUuid.toUpperCase();

        assertEquals("Users/" + lowerUuid,
                ScimCanonicalizer.extractCanonicalScimResourceTail("/Users/" + upperUuid));
        assertEquals("Users/" + lowerUuid,
                ScimCanonicalizer.extractCanonicalScimResourceTail("../Users/" + lowerUuid));
        assertEquals("Users/" + lowerUuid,
                ScimCanonicalizer.extractCanonicalScimResourceTail("https://legacy.example/scim/v1/Users/" + upperUuid + "?version=1#frag"));
        assertEquals("Groups/" + lowerUuid,
                ScimCanonicalizer.extractCanonicalScimResourceTail("https://idp.example/ws/99/scim/v2/Groups/" + lowerUuid + "/"));

        // Non-36-char IDs are preserved verbatim (never expanded via Java's lenient UUID.fromString)
        assertEquals("Users/1-2-3-4-5",
                ScimCanonicalizer.extractCanonicalScimResourceTail("/Users/1-2-3-4-5"));
        assertEquals("Users/manager-999",
                ScimCanonicalizer.extractCanonicalScimResourceTail("../Users/manager-999"));

        // Non-SCIM paths return null
        assertNull(ScimCanonicalizer.extractCanonicalScimResourceTail("https://example.com/OtherPath/" + lowerUuid));
        assertNull(ScimCanonicalizer.extractCanonicalScimResourceTail("/alice"));
        assertNull(ScimCanonicalizer.extractCanonicalScimResourceTail("   "));
        assertNull(ScimCanonicalizer.extractCanonicalScimResourceTail(null));

        assertTrue(ScimCanonicalizer.scimRefsComparable(
                "https://legacy.example/scim/v1/Users/" + upperUuid,
                "https://current.example/ws/1/scim/v2/Users/" + lowerUuid));
        assertTrue(ScimCanonicalizer.scimRefsComparable(
                "../Users/" + lowerUuid,
                "/Users/" + lowerUuid));
        assertFalse(ScimCanonicalizer.scimRefsComparable(
                "/Groups/" + lowerUuid,
                "/Users/" + lowerUuid));
        assertFalse(ScimCanonicalizer.scimRefsComparable(
                "https://example.com/OtherPath/" + lowerUuid,
                "/Users/" + lowerUuid));
    }
}
