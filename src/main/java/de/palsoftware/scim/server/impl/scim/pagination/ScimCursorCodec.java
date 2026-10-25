package de.palsoftware.scim.server.impl.scim.pagination;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.scim.error.ScimException;

import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * Codec for RFC 9865 Stateless Cursor Tokens.
 *
 * Token format: scim_cur_<base64url> (unpadded URL-safe Base64)
 * Payload format: {"w":"<workspaceUUID>","o":<zeroBasedOffset>,"exp":<unixEpochSeconds>}
 */
public final class ScimCursorCodec {

    public static final String CURSOR_PREFIX = "scim_cur_";
    public static final int DEFAULT_CURSOR_TIMEOUT_SECONDS = 3600;

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public record CursorPayload(
            @JsonProperty("w") String w,
            @JsonProperty("o") int o,
            @JsonProperty("exp") long exp
    ) {}

    private ScimCursorCodec() {
        // Utility class
    }

    /**
     * Encodes a cursor token for the given workspace, zero-based offset, and TTL in seconds.
     */
    public static String encodeCursor(UUID workspaceId, int offset, int timeoutSeconds) {
        if (workspaceId == null) {
            throw new IllegalArgumentException("workspaceId must not be null");
        }
        if (offset < 0) {
            throw new IllegalArgumentException("offset cannot be negative: " + offset);
        }
        if (timeoutSeconds <= 0) {
            throw new IllegalArgumentException("timeoutSeconds must be positive: " + timeoutSeconds);
        }

        long exp = Instant.now().getEpochSecond() + timeoutSeconds;
        CursorPayload payload = new CursorPayload(workspaceId.toString(), offset, exp);

        try {
            byte[] jsonBytes = OBJECT_MAPPER.writeValueAsBytes(payload);
            String base64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(jsonBytes);
            return CURSOR_PREFIX + base64Url;
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize cursor payload", e);
        }
    }

    /**
     * Encodes a cursor token using the default timeout of 3600 seconds.
     */
    public static String encodeCursor(UUID workspaceId, int offset) {
        return encodeCursor(workspaceId, offset, DEFAULT_CURSOR_TIMEOUT_SECONDS);
    }

    /**
     * Alias for encodeCursor(workspaceId, offset, (int) ttlSeconds).
     */
    public static String encode(UUID workspaceId, int offset, long ttlSeconds) {
        return encodeCursor(workspaceId, offset, (int) ttlSeconds);
    }

    /**
     * Alias for encodeCursor(workspaceId, offset).
     */
    public static String encode(UUID workspaceId, int offset) {
        return encodeCursor(workspaceId, offset, DEFAULT_CURSOR_TIMEOUT_SECONDS);
    }

    /**
     * Decodes and validates a cursor token for the given expected workspace.
     *
     * @param token cursor token string (empty string starts at offset 0)
     * @param workspaceId workspace UUID expected for this request
     * @return zero-based offset (>= 0)
     * @throws ScimException with HTTP 400 and scimType "invalidCursor" if invalid/expired
     */
    public static int decodeCursor(String token, UUID workspaceId) {
        if (workspaceId == null) {
            throw new IllegalArgumentException("workspaceId must not be null");
        }

        // RFC 9865 §2 & Table 1: Initial query specifies cursor="" (or empty) -> starts at offset 0
        if (token == null || token.trim().isEmpty()) {
            return 0;
        }

        if (!token.startsWith(CURSOR_PREFIX)) {
            throw new ScimException(400, "invalidCursor",
                    "Cursor must start with prefix '" + CURSOR_PREFIX + "'");
        }

        String base64Part = token.substring(CURSOR_PREFIX.length());
        if (base64Part.isEmpty()) {
            throw new ScimException(400, "invalidCursor", "Cursor token payload is empty");
        }

        byte[] jsonBytes;
        try {
            jsonBytes = Base64.getUrlDecoder().decode(base64Part);
        } catch (IllegalArgumentException e) {
            throw new ScimException(400, "invalidCursor",
                    "Malformed Base64URL in cursor token: " + e.getMessage(), e);
        }

        CursorPayload payload;
        try {
            payload = OBJECT_MAPPER.readValue(jsonBytes, CursorPayload.class);
        } catch (Exception e) {
            throw new ScimException(400, "invalidCursor",
                    "Malformed JSON payload in cursor token: " + e.getMessage(), e);
        }

        if (payload.w() == null || payload.w().isBlank()) {
            throw new ScimException(400, "invalidCursor", "Cursor missing workspace identifier");
        }

        UUID tokenWorkspaceId;
        try {
            tokenWorkspaceId = UUID.fromString(payload.w());
        } catch (IllegalArgumentException e) {
            throw new ScimException(400, "invalidCursor",
                    "Invalid workspace UUID format in cursor token: " + payload.w());
        }

        if (!workspaceId.equals(tokenWorkspaceId)) {
            throw new ScimException(400, "invalidCursor",
                    "Cursor workspace mismatch: expected " + workspaceId + " but got " + tokenWorkspaceId);
        }

        if (payload.o() < 0) {
            throw new ScimException(400, "invalidCursor",
                    "Cursor offset cannot be negative: " + payload.o());
        }

        long now = Instant.now().getEpochSecond();
        if (payload.exp() <= now) {
            throw new ScimException(400, "invalidCursor",
                    "Cursor has expired (exp=" + payload.exp() + ", now=" + now + ")");
        }

        return payload.o();
    }

    /**
     * Alias for decodeCursor(token, workspaceId).
     */
    public static int decode(String token, UUID workspaceId) {
        return decodeCursor(token, workspaceId);
    }
}
