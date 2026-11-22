package de.palsoftware.scim.server.impl.scim.error;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Shared SCIM 2.0 error serialization and cause-chain unwrapping utilities
 * for servlet filters and exception handlers (RFC 7644 §3.12).
 */
public final class ScimFilterErrorWriter {

    public static final String ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
    public static final String SCIM_CONTENT_TYPE = "application/scim+json;charset=UTF-8";

    private ScimFilterErrorWriter() {
    }

    public static Map<String, Object> buildErrorBody(int status, String scimType, String detail) {
        Map<String, Object> error = new LinkedHashMap<>(4);
        error.put("schemas", List.of(ERROR_SCHEMA));
        error.put("status", Integer.toString(status));
        if (scimType != null) {
            error.put("scimType", scimType);
        }
        if (detail != null) {
            error.put("detail", detail);
        }
        return error;
    }

    public static void writeScimError(HttpServletResponse response,
                                      ObjectMapper objectMapper,
                                      int status,
                                      String scimType,
                                      String detail) throws IOException {
        writeScimError(response, objectMapper, status, scimType, detail, null, null);
    }

    public static void writeScimError(HttpServletResponse response,
                                      ObjectMapper objectMapper,
                                      int status,
                                      String scimType,
                                      String detail,
                                      String headerName,
                                      String headerValue) throws IOException {
        Objects.requireNonNull(response, "response must not be null");
        Objects.requireNonNull(objectMapper, "objectMapper must not be null");

        response.setStatus(status);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(SCIM_CONTENT_TYPE);

        if (status == HttpServletResponse.SC_UNAUTHORIZED) {
            response.setHeader("WWW-Authenticate", "Bearer");
        }
        if (headerName != null && headerValue != null) {
            response.setHeader(headerName, headerValue);
        }

        Map<String, Object> error = buildErrorBody(status, scimType, detail);
        response.getWriter().write(objectMapper.writeValueAsString(error));
        response.getWriter().flush();
    }

    public static ScimException findScimException(Throwable throwable) {
        return findCause(throwable, ScimException.class);
    }

    public static ScimException findScimException(Throwable throwable, int httpStatus) {
        Set<Throwable> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        Throwable current = throwable;
        while (current != null && visited.add(current)) {
            if (current instanceof ScimException scimEx && scimEx.getHttpStatus() == httpStatus) {
                return scimEx;
            }
            current = current.getCause();
        }
        return null;
    }

    public static <T extends Throwable> T findCause(Throwable throwable, Class<T> type) {
        Objects.requireNonNull(type, "type must not be null");
        Set<Throwable> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        Throwable current = throwable;
        while (current != null && visited.add(current)) {
            if (type.isInstance(current)) {
                return type.cast(current);
            }
            current = current.getCause();
        }
        return null;
    }
}
