package de.palsoftware.scim.server.impl.scim.pagination;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

/**
 * Codec for RFC 9865 Stateless Cursor Tokens.
 *
 * Token format: scim_cur_<base64url(hmac16 || jsonBytes)> (unpadded URL-safe Base64)
 * Payload format: {"w":"<workspaceUUID>","o":<zeroBasedOffset>,"exp":<unixEpochSeconds>}
 */
public final class ScimCursorCodec {

    public static final String CURSOR_PREFIX = "scim_cur_";
    public static final int DEFAULT_CURSOR_TIMEOUT_SECONDS = 3600;

    private static final int HMAC_TAG_BYTES = 16;
    private static final String HMAC_ALGO = "HmacSHA256";
    private static final String DEFAULT_CLUSTER_HMAC_SECRET = "scim-cursor-default-cluster-hmac-key-v1";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static volatile byte[] hmacSecret = initHmacSecret();

    public record CursorPayload(
            @JsonProperty("w") String w,
            @JsonProperty("o") Integer o,
            @JsonProperty("exp") Long exp
    ) {}

    private ScimCursorCodec() {
        // Utility class
    }

    static byte[] deriveHmacKey(String secret) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(("scim-cursor-hmac-v1:" + secret.trim()).getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to initialize cursor HMAC key", e);
        }
    }

    private static byte[] initHmacSecret() {
        String[] candidates = {
                System.getenv("SCIM_CURSOR_SECRET"),
                System.getProperty("scim.cursor.secret"),
                System.getenv("SPRING_DATASOURCE_PASSWORD"),
                System.getProperty("spring.datasource.password"),
                System.getenv("ACTUATOR_API_KEY"),
                System.getProperty("app.security.actuator.api-key")
        };
        for (String candidate : candidates) {
            if (candidate != null && !candidate.isBlank()) {
                return deriveHmacKey(candidate);
            }
        }
        return deriveHmacKey(DEFAULT_CLUSTER_HMAC_SECRET);
    }

    public static void configureSecret(String secret) {
        if (secret != null && !secret.isBlank()) {
            hmacSecret = deriveHmacKey(secret);
        } else {
            hmacSecret = initHmacSecret();
        }
    }

    @Component
    public static class ScimCursorSecretInitializer {
        public ScimCursorSecretInitializer(@Value("${scim.cursor.secret:}") String configuredSecret) {
            if (configuredSecret != null && !configuredSecret.isBlank()) {
                ScimCursorCodec.configureSecret(configuredSecret);
            }
        }
    }

    static byte[] computeHmac(byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(hmacSecret, HMAC_ALGO));
            byte[] fullMac = mac.doFinal(data);
            return Arrays.copyOf(fullMac, HMAC_TAG_BYTES);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to compute cursor HMAC", e);
        }
    }

    private static String signAndEncode(byte[] jsonBytes) {
        byte[] mac16 = computeHmac(jsonBytes);
        byte[] combined = new byte[HMAC_TAG_BYTES + jsonBytes.length];
        System.arraycopy(mac16, 0, combined, 0, HMAC_TAG_BYTES);
        System.arraycopy(jsonBytes, 0, combined, HMAC_TAG_BYTES, jsonBytes.length);
        return CURSOR_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(combined);
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
            return signAndEncode(jsonBytes);
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
            throw new ScimException(400, "invalidCursor", "Invalid cursor prefix");
        }

        String base64Part = token.substring(CURSOR_PREFIX.length());
        if (base64Part.isEmpty()) {
            throw new ScimException(400, "invalidCursor", "Invalid cursor encoding");
        }

        byte[] decoded;
        try {
            decoded = Base64.getUrlDecoder().decode(base64Part);
        } catch (IllegalArgumentException e) {
            throw new ScimException(400, "invalidCursor", "Invalid cursor encoding");
        }

        // Reject non-canonical Base64URL representations (e.g. mutated unused trailing padding bits)
        String canonical = Base64.getUrlEncoder().withoutPadding().encodeToString(decoded);
        if (!canonical.equals(base64Part)) {
            throw new ScimException(400, "invalidCursor", "Invalid cursor encoding");
        }

        if (decoded.length <= HMAC_TAG_BYTES) {
            throw new ScimException(400, "invalidCursor", "Invalid cursor token");
        }

        byte[] mac = Arrays.copyOfRange(decoded, 0, HMAC_TAG_BYTES);
        byte[] jsonBytes = Arrays.copyOfRange(decoded, HMAC_TAG_BYTES, decoded.length);
        byte[] expectedMac = computeHmac(jsonBytes);
        if (!MessageDigest.isEqual(mac, expectedMac)) {
            throw new ScimException(400, "invalidCursor", "Invalid cursor signature");
        }

        CursorPayload payload;
        try {
            payload = OBJECT_MAPPER.readValue(jsonBytes, CursorPayload.class);
        } catch (Exception e) {
            throw new ScimException(400, "invalidCursor", "Invalid cursor payload");
        }

        if (payload.w() == null || payload.w().isBlank()) {
            throw new ScimException(400, "invalidCursor", "Invalid cursor: missing workspace");
        }

        UUID tokenWorkspaceId;
        try {
            tokenWorkspaceId = UUID.fromString(payload.w());
        } catch (IllegalArgumentException e) {
            throw new ScimException(400, "invalidCursor", "Invalid cursor: invalid workspace format");
        }

        if (!workspaceId.equals(tokenWorkspaceId)) {
            throw new ScimException(400, "invalidCursor", "Invalid cursor: workspace mismatch");
        }

        if (payload.o() == null) {
            throw new ScimException(400, "invalidCursor", "Invalid cursor: missing offset");
        }

        if (payload.o() < 0) {
            throw new ScimException(400, "invalidCursor", "Invalid cursor: negative offset");
        }

        if (payload.exp() == null) {
            throw new ScimException(400, "invalidCursor", "Invalid cursor: missing expiration");
        }

        long now = Instant.now().getEpochSecond();
        if (payload.exp() <= now) {
            throw new ScimException(400, "invalidCursor", "Invalid cursor: token has expired");
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
