package de.palsoftware.scim.server.impl.scim.util;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Enumeration;

/**
 * Utility for parsing RFC 7240 / RFC 9967 Prefer headers.
 */
public final class ScimPreferHeaderUtil {

    public static final String PREFER_HEADER = "Prefer";
    public static final String PREFERENCE_APPLIED_HEADER = "Preference-Applied";
    public static final String SET_TXN_HEADER = "Set-Txn";
    public static final String RESPOND_ASYNC_TOKEN = "respond-async";

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
}
