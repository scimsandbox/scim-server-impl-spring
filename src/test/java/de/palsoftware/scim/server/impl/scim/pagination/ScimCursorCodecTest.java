package de.palsoftware.scim.server.impl.scim.pagination;

import de.palsoftware.scim.server.impl.scim.error.ScimException;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class ScimCursorCodecTest {

    private final UUID workspaceId = UUID.randomUUID();

    @Test
    void testEncodeAndDecodeRoundtrip() {
        String token = ScimCursorCodec.encodeCursor(workspaceId, 0, 3600);
        assertNotNull(token);
        assertTrue(token.startsWith("scim_cur_"));

        int offset = ScimCursorCodec.decodeCursor(token, workspaceId);
        assertEquals(0, offset);
    }

    @Test
    void testEncodeAndDecodeArbitraryOffset() {
        String token = ScimCursorCodec.encode(workspaceId, 42);
        int offset = ScimCursorCodec.decode(token, workspaceId);
        assertEquals(42, offset);
    }

    @Test
    void testDecodeEmptyStringOrNullStartsAtZero() {
        assertEquals(0, ScimCursorCodec.decodeCursor("", workspaceId));
        assertEquals(0, ScimCursorCodec.decodeCursor("   ", workspaceId));
        assertEquals(0, ScimCursorCodec.decodeCursor(null, workspaceId));
    }

    @Test
    void testDecodeMissingPrefixThrowsInvalidCursor() {
        ScimException ex = assertThrows(ScimException.class, () ->
                ScimCursorCodec.decodeCursor("invalid-prefix-token", workspaceId));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidCursor", ex.getScimType());
        assertTrue(ex.getMessage().contains("prefix"));
    }

    @Test
    void testDecodeEmptyPayloadThrowsInvalidCursor() {
        ScimException ex = assertThrows(ScimException.class, () ->
                ScimCursorCodec.decodeCursor("scim_cur_", workspaceId));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidCursor", ex.getScimType());
    }

    @Test
    void testDecodeInvalidBase64ThrowsInvalidCursor() {
        ScimException ex = assertThrows(ScimException.class, () ->
                ScimCursorCodec.decodeCursor("scim_cur_???not-valid-base64???", workspaceId));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidCursor", ex.getScimType());
    }

    @Test
    void testDecodeMalformedJsonThrowsInvalidCursorWithoutInternalLeak() {
        String token = ScimCursorCodec.encodeRawJsonForTest("{not_json}");
        ScimException ex = assertThrows(ScimException.class, () ->
                ScimCursorCodec.decodeCursor(token, workspaceId));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidCursor", ex.getScimType());
        assertFalse(ex.getMessage().toLowerCase().contains("exception"));
    }

    @Test
    void testDecodeWorkspaceMismatchThrowsInvalidCursorWithoutUuidLeak() {
        UUID otherWorkspace = UUID.randomUUID();
        String token = ScimCursorCodec.encodeCursor(workspaceId, 10, 3600);

        ScimException ex = assertThrows(ScimException.class, () ->
                ScimCursorCodec.decodeCursor(token, otherWorkspace));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidCursor", ex.getScimType());
        assertTrue(ex.getMessage().contains("workspace mismatch"));
        assertFalse(ex.getMessage().contains(workspaceId.toString()));
        assertFalse(ex.getMessage().contains(otherWorkspace.toString()));
    }

    @Test
    void testDecodeSingleCharTamperAlwaysFailsAcrossOffsets() {
        for (int offset = 0; offset < 50; offset++) {
            String token = ScimCursorCodec.encodeCursor(workspaceId, offset, 3600);
            char last = token.charAt(token.length() - 1);
            char flipped = (last == 'a') ? 'b' : 'a';
            String tampered = token.substring(0, token.length() - 1) + flipped;

            ScimException ex = assertThrows(ScimException.class, () ->
                    ScimCursorCodec.decodeCursor(tampered, workspaceId),
                    "Tampered cursor must fail for offset " + offset);
            assertEquals(400, ex.getHttpStatus());
            assertEquals("invalidCursor", ex.getScimType());
            assertFalse(ex.getMessage().contains(workspaceId.toString()));
        }
    }

    @Test
    void testDecodeNegativeOffsetThrowsInvalidCursor() {
        long futureExp = Instant.now().getEpochSecond() + 3600;
        String rawJson = String.format("{\"w\":\"%s\",\"o\":-5,\"exp\":%d}", workspaceId, futureExp);
        String token = ScimCursorCodec.encodeRawJsonForTest(rawJson);

        ScimException ex = assertThrows(ScimException.class, () ->
                ScimCursorCodec.decodeCursor(token, workspaceId));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidCursor", ex.getScimType());
        assertTrue(ex.getMessage().contains("negative"));
    }

    @Test
    void testDecodeExpiredCursorThrowsInvalidCursor() {
        long pastExp = Instant.now().getEpochSecond() - 60; // expired 1 minute ago
        String rawJson = String.format("{\"w\":\"%s\",\"o\":10,\"exp\":%d}", workspaceId, pastExp);
        String token = ScimCursorCodec.encodeRawJsonForTest(rawJson);

        ScimException ex = assertThrows(ScimException.class, () ->
                ScimCursorCodec.decodeCursor(token, workspaceId));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidCursor", ex.getScimType());
        assertTrue(ex.getMessage().contains("expired"));
    }

    @Test
    void testTokenFormatIsUnpaddedBase64Url() {
        String token = ScimCursorCodec.encodeCursor(workspaceId, 15, 3600);
        assertTrue(token.startsWith("scim_cur_"));
        String payload = token.substring("scim_cur_".length());
        assertFalse(payload.contains("="), "Token must not contain padding '='");
        assertFalse(payload.contains("+"), "Token must not contain '+' (use URL-safe Base64)");
        assertFalse(payload.contains("/"), "Token must not contain '/' (use URL-safe Base64)");
    }

    @Test
    void testInvalidEncodeArguments() {
        assertThrows(IllegalArgumentException.class, () -> ScimCursorCodec.encodeCursor(null, 0, 3600));
        assertThrows(IllegalArgumentException.class, () -> ScimCursorCodec.encodeCursor(workspaceId, -1, 3600));
        assertThrows(IllegalArgumentException.class, () -> ScimCursorCodec.encodeCursor(workspaceId, 0, 0));
        assertThrows(IllegalArgumentException.class, () -> ScimCursorCodec.encodeCursor(workspaceId, 0, -10));
    }

    @Test
    void testDecodeMissingOffsetThrowsInvalidCursor() {
        long futureExp = Instant.now().getEpochSecond() + 3600;
        String rawJson = String.format("{\"w\":\"%s\",\"exp\":%d}", workspaceId, futureExp);
        String token = ScimCursorCodec.encodeRawJsonForTest(rawJson);

        ScimException ex = assertThrows(ScimException.class, () ->
                ScimCursorCodec.decodeCursor(token, workspaceId));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidCursor", ex.getScimType());
        assertTrue(ex.getMessage().contains("offset"));
    }

    @Test
    void testDecodeMissingExpirationThrowsInvalidCursor() {
        String rawJson = String.format("{\"w\":\"%s\",\"o\":10}", workspaceId);
        String token = ScimCursorCodec.encodeRawJsonForTest(rawJson);

        ScimException ex = assertThrows(ScimException.class, () ->
                ScimCursorCodec.decodeCursor(token, workspaceId));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidCursor", ex.getScimType());
        assertTrue(ex.getMessage().contains("expiration"));
    }

    @Test
    void testDecodeMissingWorkspaceThrowsInvalidCursor() {
        long futureExp = Instant.now().getEpochSecond() + 3600;
        String rawJson = String.format("{\"o\":10,\"exp\":%d}", futureExp);
        String token = ScimCursorCodec.encodeRawJsonForTest(rawJson);

        ScimException ex = assertThrows(ScimException.class, () ->
                ScimCursorCodec.decodeCursor(token, workspaceId));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidCursor", ex.getScimType());
        assertTrue(ex.getMessage().contains("workspace"));
    }
}
