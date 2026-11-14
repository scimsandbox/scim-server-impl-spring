package de.palsoftware.scim.server.impl.scim.validation;

import de.palsoftware.scim.server.impl.scim.error.ScimException;

import java.text.Normalizer;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * RFC 7643 / RFC 7644 §7.8 attribute type validation, Unicode NFC preparation,
 * and value canonicalization utilities.
 */
public final class ScimCanonicalizer {

    // Compact E.164 (+ followed by 2..15 digits, no visual separators or parameters)
    private static final Pattern COMPACT_E164 = Pattern.compile("^\\+[1-9][0-9]{1,14}$");
    private static final Pattern SCIM_RESOURCE_REF_TAIL = Pattern.compile("(?i)(?:^|/)(Users|Groups)/([^/?#]+)$");

    private ScimCanonicalizer() {
    }

    public static String normalizeNfc(String value) {
        return value == null ? null : Normalizer.normalize(value, Normalizer.Form.NFC);
    }

    public static String requireNullableString(Object raw, String fieldName) {
        if (raw == null) {
            return null;
        }
        if (raw instanceof String s) {
            return normalizeNfc(s);
        }
        throw new ScimException(400, "invalidValue",
                "Attribute '" + fieldName + "' must be a string");
    }

    public static boolean requireBoolean(Object raw, String fieldName, boolean defaultValue) {
        if (raw == null) {
            return defaultValue;
        }
        if (raw instanceof Boolean b) {
            return b;
        }
        throw new ScimException(400, "invalidValue",
                "Attribute '" + fieldName + "' must be a boolean");
    }

    /**
     * Normalizes a SCIM 'type' sub-attribute case-insensitively to canonical lowercase
     * when matching an entry in {@code canonicalValues}, while preserving custom
     * non-canonical values per RFC 7643 §7 ("canonicalValues" are advisory).
     */
    public static String canonicalizeType(Object rawType, Set<String> canonicalValues,
                                          String defaultWhenNull, String fieldName) {
        String s = requireNullableString(rawType, fieldName);
        if (s == null || s.isBlank()) {
            return defaultWhenNull;
        }
        String trimmed = s.trim();
        if (canonicalValues != null) {
            for (String canonical : canonicalValues) {
                if (canonical.equalsIgnoreCase(trimmed)) {
                    return canonical;
                }
            }
        }
        return trimmed;
    }

    /**
     * Canonicalizes an email address per RFC 5321 / RFC 7643 §4.1.2:
     * preserves local-part case and lowercases the domain part.
     */
    public static String canonicalizeEmail(String raw) {
        if (raw == null) {
            return null;
        }
        String trimmed = normalizeNfc(raw.trim());
        int atIdx = trimmed.lastIndexOf('@');
        if (atIdx > 0 && atIdx < trimmed.length() - 1) {
            String local = trimmed.substring(0, atIdx);
            String domain = trimmed.substring(atIdx + 1).toLowerCase(Locale.ROOT);
            return local + "@" + domain;
        }
        return trimmed;
    }

    /**
     * Canonicalizes phone numbers per RFC 7643 §4.1.2 / RFC 3966:
     * - Existing 'tel:' URIs are normalized to RFC 3966 visual-separator form.
     * - Formatted international numbers ('+1 (201) 555-0123') and contextual numbers
     *   (';phone-context=') are canonicalized to 'tel:+1-201-555-0123'.
     * - Already-compact E.164 strings ('+155733333333') and bare local strings ('123-456')
     *   without ';phone-context=' are preserved as-is.
     */
    public static String canonicalizePhoneNumber(String raw) {
        if (raw == null) {
            return null;
        }
        String trimmed = normalizeNfc(raw.trim());
        if (trimmed.isEmpty()) {
            return trimmed;
        }
        if (trimmed.regionMatches(true, 0, "tel:", 0, 4)) {
            String rest = trimmed.substring(4).trim();
            return "tel:" + normalizeTelBody(rest);
        }
        if (trimmed.toLowerCase(Locale.ROOT).contains(";phone-context=")) {
            return "tel:" + normalizeTelBody(trimmed);
        }
        if (trimmed.startsWith("+")) {
            if (COMPACT_E164.matcher(trimmed).matches()) {
                return trimmed;
            }
            return "tel:" + normalizeTelBody(trimmed);
        }
        return trimmed;
    }

    private static String normalizeTelBody(String body) {
        int semi = body.indexOf(';');
        String numberPart = semi >= 0 ? body.substring(0, semi) : body;
        String paramsPart = semi >= 0 ? body.substring(semi).replaceAll("\\s+", "") : "";
        String cleaned = numberPart
                .replace("(", "")
                .replace(")", "")
                .trim()
                .replaceAll("[\\s.]+", "-")
                .replaceAll("-{2,}", "-")
                .replaceAll("^\\+-", "+")
                .replaceAll("-$", "");
        return cleaned + paramsPart;
    }

    /**
     * Canonicalizes instant messaging handles per RFC 7643 §4.1.2 by stripping
     * whitespace and lowercasing.
     */
    public static String canonicalizeIm(String raw) {
        if (raw == null) {
            return null;
        }
        return normalizeNfc(raw).replaceAll("\\s+", "").toLowerCase(Locale.ROOT);
    }

    /**
     * Extracts a version-agnostic canonical SCIM resource tail ({@code "Users/<id>"} or
     * {@code "Groups/<id>"}) from a SCIM reference URI per RFC 7643 §2.4 (RFC7643-2.4-63934b),
     * or {@code null} if {@code ref} is not a SCIM User/Group URI.
     */
    public static String extractCanonicalScimResourceTail(String ref) {
        if (ref == null || ref.isBlank()) {
            return null;
        }
        String cleaned = normalizeNfc(ref.trim());
        int qIdx = cleaned.indexOf('?');
        if (qIdx >= 0) {
            cleaned = cleaned.substring(0, qIdx);
        }
        int fIdx = cleaned.indexOf('#');
        if (fIdx >= 0) {
            cleaned = cleaned.substring(0, fIdx);
        }
        while (cleaned.length() > 1 && cleaned.endsWith("/")) {
            cleaned = cleaned.substring(0, cleaned.length() - 1);
        }
        Matcher matcher = SCIM_RESOURCE_REF_TAIL.matcher(cleaned);
        if (!matcher.find()) {
            return null;
        }
        String resource = "groups".equalsIgnoreCase(matcher.group(1)) ? "Groups" : "Users";
        String rawId = matcher.group(2);
        if (rawId.length() == 36) {
            try {
                UUID parsed = UUID.fromString(rawId);
                if (parsed.toString().equalsIgnoreCase(rawId)) {
                    rawId = parsed.toString();
                }
            } catch (IllegalArgumentException _) {
                // Preserve non-UUID identifiers as-is
            }
        }
        return resource + "/" + rawId;
    }

    /**
     * Compares two SCIM {@code $ref} URIs per RFC 7643 §2.4 (RFC7643-2.4-63934b):
     * URIs targeting the same SCIM resource with an API version, a different API version,
     * or without an API version are considered comparable.
     */
    public static boolean scimRefsComparable(String refA, String refB) {
        if (refA == null || refB == null) {
            return false;
        }
        String normA = normalizeNfc(refA);
        String normB = normalizeNfc(refB);
        if (normA.equals(normB)) {
            return true;
        }
        String tailA = extractCanonicalScimResourceTail(normA);
        String tailB = extractCanonicalScimResourceTail(normB);
        return tailA != null && tailA.equals(tailB);
    }
}
