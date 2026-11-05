package de.palsoftware.scim.server.impl.scim.pagination;

import java.time.Instant;
import java.util.UUID;

/**
 * Test-only bridge for generating signed raw/expired cursor payloads without sleeping or reflection.
 */
public final class ScimCursorTestHelper {

    private ScimCursorTestHelper() {
    }

    public static String encodeSignedRawJson(String rawJson) {
        return ScimCursorCodec.encodeRawJsonForTest(rawJson);
    }

    public static String encodeExpiredCursor(UUID workspaceId, int offset) {
        long expiredEpoch = Instant.now().getEpochSecond() - 60;
        String json = "{\"w\":\"" + workspaceId + "\",\"o\":" + offset + ",\"exp\":" + expiredEpoch + "}";
        return ScimCursorCodec.encodeRawJsonForTest(json);
    }
}
