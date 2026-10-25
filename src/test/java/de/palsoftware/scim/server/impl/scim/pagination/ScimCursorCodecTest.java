package de.palsoftware.scim.server.impl.scim.pagination;

import de.palsoftware.scim.server.impl.scim.error.ScimException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
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
    void testDecodeMalformedJsonThrowsInvalidCursor() {
        String badJson = Base64.getUrlEncoder().withoutPadding().encodeToString("{not_json}".getBytes(StandardCharsets.UTF_8));
        ScimException ex = assertThrows(ScimException.class, () ->
                ScimCursorCodec.decodeCursor("scim_cur_" + badJson, workspaceId));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidCursor", ex.getScimType());
    }

    @Test
    void testDecodeWorkspaceMismatchThrowsInvalidCursor() {
        UUID otherWorkspace = UUID.randomUUID();
        String token = ScimCursorCodec.encodeCursor(workspaceId, 10, 3600);

        ScimException ex = assertThrows(ScimException.class, () ->
                ScimCursorCodec.decodeCursor(token, otherWorkspace));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidCursor", ex.getScimType());
        assertTrue(ex.getMessage().contains("workspace mismatch"));
    }

    @Test
    void testDecodeNegativeOffsetThrowsInvalidCursor() {
        long futureExp = Instant.now().getEpochSecond() + 3600;
        String rawJson = String.format("{\"w\":\"%s\",\"o\":-5,\"exp\":%d}", workspaceId, futureExp);
        String base64 = Base64.getUrlEncoder().withoutPadding().encodeToString(rawJson.getBytes(StandardCharsets.UTF_8));

        ScimException ex = assertThrows(ScimException.class, () ->
                ScimCursorCodec.decodeCursor("scim_cur_" + base64, workspaceId));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidCursor", ex.getScimType());
        assertTrue(ex.getMessage().contains("negative"));
    }

    @Test
    void testDecodeExpiredCursorThrowsInvalidCursor() {
        long pastExp = Instant.now().getEpochSecond() - 60; // expired 1 minute ago
        String rawJson = String.format("{\"w\":\"%s\",\"o\":10,\"exp\":%d}", workspaceId, pastExp);
        String base64 = Base64.getUrlEncoder().withoutPadding().encodeToString(rawJson.getBytes(StandardCharsets.UTF_8));

        ScimException ex = assertThrows(ScimException.class, () ->
                ScimCursorCodec.decodeCursor("scim_cur_" + base64, workspaceId));
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
}
