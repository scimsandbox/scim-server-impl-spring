package de.palsoftware.scim.server.impl.scim.util;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Enumeration;
import java.util.OptionalInt;

/**
 * Utility for parsing RFC 7240 / RFC 9967 Prefer headers.
 */
public final class ScimPreferHeaderUtil {

    public static final String PREFER_HEADER = "Prefer";
    public static final String PREFERENCE_APPLIED_HEADER = "Preference-Applied";
    public static final String SET_TXN_HEADER = "Set-Txn";
    public static final String RESPOND_ASYNC_TOKEN = "respond-async";
    public static final String WAIT_TOKEN = "wait";

    private ScimPreferHeaderUtil() {}

    /**
     * Checks if the HTTP request contains a Prefer header with the respond-async token.
     *
     * @param request the HTTP request
     * @return true if respond-async is requested
     */
    public static boolean hasRespondAsync(HttpServletRequest request) {
        if (request == null) {
            return false;
        }
        Enumeration<String> headers = request.getHeaders(PREFER_HEADER);
        if (headers == null) {
            return false;
        }
        while (headers.hasMoreElements()) {
            String header = headers.nextElement();
            if (hasRespondAsync(header)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Parses a Prefer header string to check for the respond-async token per RFC 7240 §4.1.
     *
     * @param preferHeader the header value
     * @return true if respond-async is present
     */
    public static boolean hasRespondAsync(String preferHeader) {
        if (preferHeader == null || preferHeader.isBlank()) {
            return false;
        }
        String[] tokens = preferHeader.split(",");
        for (String token : tokens) {
            String trimmed = token.trim();
            int semiIdx = trimmed.indexOf(';');
            String preference = (semiIdx >= 0) ? trimmed.substring(0, semiIdx).trim() : trimmed;
            if (RESPOND_ASYNC_TOKEN.equalsIgnoreCase(preference)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extracts the RFC 7240 §4.3 {@code wait} preference value in seconds if present.
     * Supports both comma-separated ({@code Prefer: respond-async, wait=10}) and
     * semicolon parameter ({@code Prefer: respond-async; wait=10}) forms.
     */
    public static OptionalInt getWaitSeconds(HttpServletRequest request) {
        if (request == null) {
            return OptionalInt.empty();
        }
        Enumeration<String> headers = request.getHeaders(PREFER_HEADER);
        if (headers == null) {
            return OptionalInt.empty();
        }
        while (headers.hasMoreElements()) {
            OptionalInt parsed = getWaitSeconds(headers.nextElement());
            if (parsed.isPresent()) {
                return parsed;
            }
        }
        return OptionalInt.empty();
    }

    public static OptionalInt getWaitSeconds(String preferHeader) {
        if (preferHeader == null || preferHeader.isBlank()) {
            return OptionalInt.empty();
        }
        String[] commaTokens = preferHeader.split(",");
        for (String token : commaTokens) {
            String[] semiParts = token.split(";");
            for (String part : semiParts) {
                String trimmed = part.trim();
                int eqIdx = trimmed.indexOf('=');
                if (eqIdx > 0) {
                    String name = trimmed.substring(0, eqIdx).trim();
                    String rawVal = unquoteHeaderToken(trimmed.substring(eqIdx + 1).trim());
                    if (WAIT_TOKEN.equalsIgnoreCase(name)) {
                        try {
                            int seconds = Integer.parseInt(rawVal);
                            if (seconds >= 0) {
                                return OptionalInt.of(seconds);
                            }
                        } catch (NumberFormatException ignored) {
                            // Ignore malformed wait value per RFC 7240 §2
                        }
                    }
                }
            }
        }
        return OptionalInt.empty();
    }

    /**
     * Determines whether the request should be dispatched asynchronously (returning 202 Accepted).
     * Per RFC 9967 §2.5.1.1 and RFC 7240 §4.3, when {@code wait=N} (with {@code N > 0}) is sent,
     * the client prefers waiting up to N seconds for synchronous completion before falling back to 202.
     */
    public static boolean shouldExecuteAsync(HttpServletRequest request) {
        if (!hasRespondAsync(request)) {
            return false;
        }
        OptionalInt wait = getWaitSeconds(request);
        if (wait.isPresent() && wait.getAsInt() > 0) {
            return false;
        }
        return true;
    }

    public static String buildPreferenceAppliedHeader(HttpServletRequest request) {
        OptionalInt wait = getWaitSeconds(request);
        if (wait.isPresent() && wait.getAsInt() == 0) {
            return RESPOND_ASYNC_TOKEN + ", wait=0";
        }
        return RESPOND_ASYNC_TOKEN;
    }

    private static String unquoteHeaderToken(String value) {
        if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1);
        }
        return value;
    }
}
