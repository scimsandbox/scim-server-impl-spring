package de.palsoftware.scim.server.impl.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Custom ErrorController that ensures any servlet-level or unhandled container errors
 * forwarded to /error produce a SCIM 2.0 compliant error representation (RFC 7644 §3.12)
 * without leaking internal exception messages.
 */
@RestController
public class ScimErrorController implements ErrorController {

    private static final Logger log = LoggerFactory.getLogger(ScimErrorController.class);
    private static final String ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
    private static final MediaType SCIM_JSON = MediaType.parseMediaType("application/scim+json;charset=UTF-8");

    @RequestMapping("/error")
    public ResponseEntity<Map<String, Object>> handleError(HttpServletRequest request) {
        Integer statusCode = (Integer) request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        if (statusCode == null) {
            statusCode = 500;
        }

        Throwable throwable = (Throwable) request.getAttribute(RequestDispatcher.ERROR_EXCEPTION);
        String errorUri = (String) request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI);

        String detail;
        if (statusCode >= 500) {
            if (throwable != null) {
                log.error("Unhandled server error (status={}) on URI={}", statusCode, errorUri, throwable);
            } else {
                log.error("Unhandled server error (status={}) on URI={}", statusCode, errorUri);
            }
            detail = "An unexpected internal error occurred.";
        } else {
            detail = switch (statusCode) {
                case 400 -> "Bad request";
                case 401 -> "Unauthorized";
                case 403 -> "Forbidden";
                case 404 -> "Resource not found";
                case 405 -> "Method not allowed";
                case 406 -> "Not Acceptable";
                case 413 -> "Payload Too Large";
                case 415 -> "Unsupported Media Type";
                case 429 -> "Too Many Requests";
                default -> "Request error";
            };
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("schemas", List.of(ERROR_SCHEMA));
        body.put("status", String.valueOf(statusCode));
        body.put("detail", detail);

        return ResponseEntity.status(statusCode)
                .contentType(SCIM_JSON)
                .body(body);
    }
}
