package de.palsoftware.scim.server.impl.scim.error;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

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

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<Map<String, Object>> handleMediaTypeNotSupported(HttpMediaTypeNotSupportedException ex) {
        return buildErrorResponse(415, null, "Unsupported Media Type: " + ex.getContentType());
    }

    @ExceptionHandler(HttpMediaTypeNotAcceptableException.class)
    public ResponseEntity<Map<String, Object>> handleMediaTypeNotAcceptable(HttpMediaTypeNotAcceptableException ex) {
        return buildErrorResponse(406, null, "Not Acceptable: " + ex.getMessage());
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNoResourceFound(NoResourceFoundException ex) {
        return buildErrorResponse(404, null, "Resource not found: " + ex.getResourcePath());
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<Map<String, Object>> handleDataIntegrityViolation(DataIntegrityViolationException ex) {
        log.warn("Data integrity violation: {}", ex.getMessage());
        return buildErrorResponse(409, "uniqueness", "A resource with this identifier or unique attribute already exists");
    }

    @ExceptionHandler(TransactionSystemException.class)
    public ResponseEntity<Map<String, Object>> handleTransactionSystemException(TransactionSystemException ex) {
        Throwable cause = ex.getRootCause();
        if (cause instanceof ScimException se) {
            return handleScimException(se);
        }
        if (cause instanceof org.hibernate.exception.ConstraintViolationException) {
            return buildErrorResponse(409, "uniqueness", "A resource with this identifier or unique attribute already exists");
        }
        log.error("Transaction exception in SCIM controller", ex);
        return buildErrorResponse(500, null, "Transaction error: " + (cause != null ? cause.getMessage() : ex.getMessage()));
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, MissingServletRequestParameterException.class, IllegalArgumentException.class})
    public ResponseEntity<Map<String, Object>> handleBadRequest(Exception ex) {
        return buildErrorResponse(400, "invalidValue", ex.getMessage());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGeneral(Exception ex) {
        Throwable cause = ex;
        while (cause.getCause() != null && cause.getCause() != cause) {
            cause = cause.getCause();
            if (cause instanceof ScimException se) {
                return handleScimException(se);
            }
            if (cause instanceof DataIntegrityViolationException dive) {
                return handleDataIntegrityViolation(dive);
            }
        }
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
