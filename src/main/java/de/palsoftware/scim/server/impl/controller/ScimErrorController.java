package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.scim.error.ScimFilterErrorWriter;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Custom ErrorController that ensures any servlet-level or unhandled container errors
 * forwarded to /error produce a SCIM 2.0 compliant error representation (RFC 7644 §3.12)
 * without leaking internal exception messages or duplicating container exception logs.
 */
@RestController
public class ScimErrorController implements ErrorController {

    private static final MediaType SCIM_JSON = MediaType.parseMediaType(ScimFilterErrorWriter.SCIM_CONTENT_TYPE);

    @RequestMapping("/error")
    public ResponseEntity<Map<String, Object>> handleError(HttpServletRequest request) {
        Integer statusCode = (Integer) request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        if (statusCode == null) {
            statusCode = 500;
        }

        String detail;
        if (statusCode >= 500) {
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

        return ResponseEntity.status(statusCode)
                .contentType(SCIM_JSON)
                .body(ScimFilterErrorWriter.buildErrorBody(statusCode, null, detail));
    }
}
