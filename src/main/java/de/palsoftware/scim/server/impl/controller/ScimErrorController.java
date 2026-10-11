package de.palsoftware.scim.server.impl.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
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
 * forwarded to /error produce a SCIM 2.0 compliant error representation (RFC 7644 §3.12).
 */
@RestController
public class ScimErrorController implements ErrorController {

    private static final String ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
    private static final MediaType SCIM_JSON = MediaType.parseMediaType("application/scim+json;charset=UTF-8");

    @RequestMapping("/error")
    public ResponseEntity<Map<String, Object>> handleError(HttpServletRequest request) {
        Integer statusCode = (Integer) request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        if (statusCode == null) {
            statusCode = 500;
        }

        String message = (String) request.getAttribute(RequestDispatcher.ERROR_MESSAGE);
        Throwable throwable = (Throwable) request.getAttribute(RequestDispatcher.ERROR_EXCEPTION);

        String detail;
        if (message != null && !message.isBlank()) {
            detail = message;
        } else if (throwable != null && throwable.getMessage() != null && !throwable.getMessage().isBlank()) {
            detail = throwable.getMessage();
        } else if (statusCode == 404) {
            detail = "Resource not found";
        } else if (statusCode == 405) {
            detail = "Method not allowed";
        } else if (statusCode == 415) {
            detail = "Unsupported Media Type";
        } else if (statusCode == 406) {
            detail = "Not Acceptable";
        } else {
            detail = "Server error";
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
