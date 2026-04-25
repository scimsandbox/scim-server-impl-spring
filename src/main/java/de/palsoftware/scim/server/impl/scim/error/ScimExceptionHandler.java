package de.palsoftware.scim.server.impl.scim.error;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Global exception handler that produces SCIM-compliant error responses.
 */
@RestControllerAdvice(basePackages = "de.palsoftware.scim.server.impl.controller")
public class ScimExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ScimExceptionHandler.class);
    private static final String ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";

    @ExceptionHandler(ScimException.class)
    public ResponseEntity<Map<String, Object>> handleScimException(ScimException ex) {
        return buildErrorResponse(ex.getHttpStatus(), ex.getScimType(), ex.getMessage());
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleBadJson(HttpMessageNotReadableException ex) {
        return buildErrorResponse(400, "invalidSyntax", "Invalid or malformed JSON in request body");
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<Map<String, Object>> handleMethodNotAllowed(HttpRequestMethodNotSupportedException ex) {
        return buildErrorResponse(405, null, "Method " + ex.getMethod() + " not allowed");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGeneral(Exception ex) {
        log.error("Unhandled exception in SCIM controller", ex);
        return buildErrorResponse(500, null, "Internal server error");
    }

    private ResponseEntity<Map<String, Object>> buildErrorResponse(int status, String scimType, String detail) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("schemas", List.of(ERROR_SCHEMA));
        body.put("status", String.valueOf(status));
        if (scimType != null) body.put("scimType", scimType);
        body.put("detail", detail);

        return ResponseEntity.status(status)
                .header("Content-Type", "application/scim+json;charset=UTF-8")
                .body(body);
    }
}
