package de.palsoftware.scim.server.impl.controller;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * SCIM 2.0 /Me endpoint per RFC 7644 §3.11.
 * Returns 501 Not Implemented — the /Me alias requires a mapping from
 * the authenticated subject to a SCIM resource, which is not supported.
 */
@RestController
@RequestMapping({"/ws/{workspaceId}/scim/v2/Me", "/ws/{workspaceId}/scim/v2/{compat}/Me"})
public class ScimMeController {

    private static final MediaType SCIM_JSON = MediaType.parseMediaType("application/scim+json");

    @RequestMapping(method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT,
            RequestMethod.PATCH, RequestMethod.DELETE})
    public ResponseEntity<Map<String, Object>> meNotImplemented(
            @PathVariable(name = "compat", required = false) String compat) {
        Map<String, Object> error = new LinkedHashMap<>();
        error.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:Error"));
        error.put("status", "501");
        error.put("detail", "The /Me endpoint is not supported");
        return ResponseEntity.status(501)
                .contentType(SCIM_JSON)
                .body(error);
    }
}
