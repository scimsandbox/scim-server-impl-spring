package de.palsoftware.scim.server.impl.scim.pagination;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * Test-only bridge for generating signed raw/expired cursor payloads without sleeping or reflection.
 */
public final class ScimCursorTestHelper {

    private ScimCursorTestHelper() {
    }

    public static String encodeRawJsonForTest(String rawJson) {
        byte[] jsonBytes = rawJson.getBytes(StandardCharsets.UTF_8);
        byte[] mac16 = ScimCursorCodec.computeHmac(jsonBytes);
        byte[] combined = new byte[mac16.length + jsonBytes.length];
        System.arraycopy(mac16, 0, combined, 0, mac16.length);
        System.arraycopy(jsonBytes, 0, combined, mac16.length, jsonBytes.length);
        return ScimCursorCodec.CURSOR_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(combined);
    }

    public static String encodeSignedRawJson(String rawJson) {
        return encodeRawJsonForTest(rawJson);
    }

    public static String encodeExpiredCursor(UUID workspaceId, int offset) {
        long expiredEpoch = Instant.now().getEpochSecond() - 60;
        String json = "{\"w\":\"" + workspaceId + "\",\"o\":" + offset + ",\"exp\":" + expiredEpoch + "}";
        return encodeRawJsonForTest(json);
    }
}
