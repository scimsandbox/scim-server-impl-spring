package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.schema.ScimSchemaDefinitions;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * SCIM 2.0 Discovery Endpoints per RFC 7643 §5/§6/§7.
 * - /ServiceProviderConfig
 * - /Schemas, /Schemas/{id}
 * - /ResourceTypes, /ResourceTypes/{id}
 *
 * Only GET is allowed; POST/PUT/PATCH/DELETE return 405.
 */
@RestController
@RequestMapping({"/ws/{workspaceId}/scim/v2", "/ws/{workspaceId}/scim/v2/{compat}"})
public class ScimDiscoveryController extends ScimBaseController {

    private static final MediaType SCIM_JSON = MediaType.parseMediaType("application/scim+json");

    // ─── ServiceProviderConfig ──────────────────────────────────────────

    @GetMapping("/ServiceProviderConfig")
        public ResponseEntity<Map<String, Object>> getServiceProviderConfig(
            @PathVariable(name = "compat", required = false) String compat) {
        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .body(ScimSchemaDefinitions.serviceProviderConfig());
    }

    @RequestMapping(value = "/ServiceProviderConfig", method = {RequestMethod.POST, RequestMethod.PUT,
            RequestMethod.PATCH, RequestMethod.DELETE})
    public ResponseEntity<Map<String, Object>> serviceProviderConfigMethodNotAllowed(
            @PathVariable(name = "compat", required = false) String compat) {
        return methodNotAllowed();
    }

    // ─── Schemas ────────────────────────────────────────────────────────

    @GetMapping("/Schemas")
    public ResponseEntity<Map<String, Object>> getSchemas(
            @PathVariable(name = "compat", required = false) String compat) {
        List<Map<String, Object>> schemas = ScimSchemaDefinitions.allSchemas();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put(KEY_SCHEMAS, List.of("urn:ietf:params:scim:api:messages:2.0:ListResponse"));
        response.put("totalResults", schemas.size());
        response.put("itemsPerPage", schemas.size());
        response.put("startIndex", 1);
        response.put("Resources", schemas);
        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .body(response);
    }

    @GetMapping("/Schemas/{schemaId}")
        public ResponseEntity<Map<String, Object>> getSchemaById(
            @PathVariable String schemaId,
            @PathVariable(name = "compat", required = false) String compat) {
        // The schema ID is a URN like urn:ietf:params:scim:schemas:core:2.0:User
        // but Spring URL-decodes it, so colons should be preserved
        Map<String, Object> schema = ScimSchemaDefinitions.getSchemaById(schemaId);
        if (schema == null) {
            throw new ScimException(404, null, "Schema not found: " + schemaId);
        }
        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .body(schema);
    }

    @RequestMapping(value = {"/Schemas", "/Schemas/{schemaId}"}, method = {RequestMethod.POST,
            RequestMethod.PUT, RequestMethod.PATCH, RequestMethod.DELETE})
    public ResponseEntity<Map<String, Object>> schemasMethodNotAllowed(
            @PathVariable(name = "schemaId", required = false) String schemaId,
            @PathVariable(name = "compat", required = false) String compat) {
        return methodNotAllowed();
    }

    // ─── ResourceTypes ──────────────────────────────────────────────────

    @GetMapping("/ResourceTypes")
    public ResponseEntity<Map<String, Object>> getResourceTypes(HttpServletRequest request,
            @PathVariable String workspaceId,
            @PathVariable(name = "compat", required = false) String compat) {
        String baseUrl = buildBaseUrl(request, workspaceId, compat);
        List<Map<String, Object>> types = ScimSchemaDefinitions.resourceTypes(baseUrl);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put(KEY_SCHEMAS, List.of("urn:ietf:params:scim:api:messages:2.0:ListResponse"));
        response.put("totalResults", types.size());
        response.put("itemsPerPage", types.size());
        response.put("startIndex", 1);
        response.put("Resources", types);
        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .body(response);
    }

    @GetMapping("/ResourceTypes/{resourceTypeId}")
    public ResponseEntity<Map<String, Object>> getResourceTypeById(@PathVariable String resourceTypeId,
            HttpServletRequest request, @PathVariable String workspaceId,
            @PathVariable(name = "compat", required = false) String compat) {
        String baseUrl = buildBaseUrl(request, workspaceId, compat);
        Map<String, Object> rt = ScimSchemaDefinitions.getResourceTypeById(resourceTypeId, baseUrl);
        if (rt == null) {
            throw new ScimException(404, null, "ResourceType not found: " + resourceTypeId);
        }
        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .body(rt);
    }

    @RequestMapping(value = {"/ResourceTypes", "/ResourceTypes/{resourceTypeId}"}, method = {RequestMethod.POST,
            RequestMethod.PUT, RequestMethod.PATCH, RequestMethod.DELETE})
    public ResponseEntity<Map<String, Object>> resourceTypesMethodNotAllowed(
            @PathVariable(name = "resourceTypeId", required = false) String resourceTypeId,
            @PathVariable(name = "compat", required = false) String compat) {
        return methodNotAllowed();
    }

    // ─── Helpers ────────────────────────────────────────────────────────

    private ResponseEntity<Map<String, Object>> methodNotAllowed() {
        Map<String, Object> error = new LinkedHashMap<>();
        error.put(KEY_SCHEMAS, List.of("urn:ietf:params:scim:api:messages:2.0:Error"));
        error.put("status", "405");
        error.put("detail", "Method not allowed on discovery endpoint");
        return ResponseEntity.status(405)
                .contentType(SCIM_JSON)
                .body(error);
    }

}
