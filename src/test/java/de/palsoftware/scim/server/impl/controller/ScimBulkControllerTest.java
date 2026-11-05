package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.service.ScimGroupService;
import de.palsoftware.scim.server.impl.service.ScimUserService;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

class ScimBulkControllerTest {

    private ScimUserService userService;
    private ScimGroupService groupService;
    private ScimBulkController controller;
    private final UUID workspaceId = UUID.randomUUID();
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        userService = Mockito.mock(ScimUserService.class);
        groupService = Mockito.mock(ScimGroupService.class);
        controller = new ScimBulkController(userService, groupService);

        request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("localhost");
        request.setServerPort(8080);
        request.setRequestURI("/ws/" + workspaceId + "/scim/v2/Bulk");
    }

    @Test
    void testProcessBulk_EmptyOps_ThrowsException() {
        Map<String, Object> body = new HashMap<>(); // missing Operations
        body.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"));
        String workspaceIdValue = workspaceId.toString();
        Exception e = assertThrows(Exception.class,
            () -> controller.processBulk(workspaceIdValue, body, null, request));
        assertTrue(e.getMessage().contains("Bulk request must contain Operations"));
    }

    @Test
    void testProcessBulk_TooManyOps_ThrowsException() {
        Map<String, Object> body = new HashMap<>();
        body.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"));
        List<Map<String, Object>> ops = new ArrayList<>();
        for (int i = 0; i < 1001; i++) {
            ops.add(Map.of());
        }
        body.put("Operations", ops);

        String workspaceIdValue = workspaceId.toString();
        Exception e = assertThrows(Exception.class,
                () -> controller.processBulk(workspaceIdValue, body, null, request));
        assertTrue(e.getMessage().contains("exceeds maxOperations"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testProcessBulk_PostUserAndGroup() {
        ScimUser user = new ScimUser();
        user.setId(UUID.randomUUID());
        when(userService.createUser(eq(workspaceId), any())).thenReturn(user);

        ScimGroup group = new ScimGroup();
        group.setId(UUID.randomUUID());
        when(groupService.createGroup(eq(workspaceId), any())).thenReturn(group);

        Map<String, Object> op1 = new HashMap<>();
        op1.put("method", "POST");
        op1.put("path", "/Users");
        op1.put("bulkId", "qwerty");
        op1.put("data", Map.of("userName", "test"));

        Map<String, Object> op2 = new HashMap<>();
        op2.put("method", "POST");
        op2.put("path", "/Groups");
        op2.put("bulkId", "ytrewq");
        op2.put("data", Map.of("displayName", "group1", "members", List.of(Map.of("value", "bulkId:qwerty"))));

        Map<String, Object> body = Map.of(
                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"),
                "Operations", List.of(op1, op2));

        ResponseEntity<Map<String, Object>> response = controller.processBulk(workspaceId.toString(), body, null,
                request);

        assertEquals(200, response.getStatusCode().value());
        List<Map<String, Object>> results = (List<Map<String, Object>>) response.getBody().get("Operations");
        assertEquals(2, results.size());

        assertEquals("POST", results.get(0).get("method"));
        assertEquals("201", results.get(0).get("status"));
        assertTrue(((String) results.get(0).get("location")).contains(user.getId().toString()));
        assertEquals("qwerty", results.get(0).get("bulkId"));

        assertEquals("POST", results.get(1).get("method"));
        assertEquals("201", results.get(1).get("status"));
        assertTrue(((String) results.get(1).get("location")).contains(group.getId().toString()));
        assertEquals("ytrewq", results.get(1).get("bulkId"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testProcessBulk_PutPatchDelete() {
        UUID userId = UUID.randomUUID();
        ScimUser mockUser = new ScimUser();
        mockUser.setId(userId);
        when(userService.replaceUser(eq(workspaceId), eq(userId), any(), any())).thenReturn(mockUser);
        when(userService.patchUser(eq(workspaceId), eq(userId), any(), any())).thenReturn(mockUser);

        UUID groupId = UUID.randomUUID();
        ScimGroup mockGroup = new ScimGroup();
        mockGroup.setId(groupId);
        when(groupService.replaceGroup(eq(workspaceId), eq(groupId), any(), any())).thenReturn(mockGroup);
        when(groupService.patchGroup(eq(workspaceId), eq(groupId), any(), any())).thenReturn(mockGroup);

        Map<String, Object> opUserPut = Map.of("method", "PUT", "path", "/Users/" + userId, "data", Map.of());
        Map<String, Object> opGroupPut = Map.of("method", "PUT", "path", "/Groups/" + groupId, "data", Map.of());
        Map<String, Object> opUserPatch = Map.of("method", "PATCH", "path", "/Users/" + userId, "data", Map.of());
        Map<String, Object> opGroupPatch = Map.of("method", "PATCH", "path", "/Groups/" + groupId, "data", Map.of());
        Map<String, Object> opUserDelete = Map.of("method", "DELETE", "path", "/Users/" + userId);
        Map<String, Object> opGroupDelete = Map.of("method", "DELETE", "path", "/Groups/" + groupId);
        Map<String, Object> opInvalidMethod = Map.of("method", "INVALID", "path", "/Users/" + userId);

        Map<String, Object> body = Map.of(
                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"),
                "Operations", List.of(
                opUserPut, opGroupPut, opUserPatch, opGroupPatch, opUserDelete, opGroupDelete, opInvalidMethod));

        ResponseEntity<Map<String, Object>> response = controller.processBulk(workspaceId.toString(), body, null,
                request);

        assertEquals(200, response.getStatusCode().value());
        List<Map<String, Object>> results = (List<Map<String, Object>>) response.getBody().get("Operations");
        assertEquals(7, results.size());

        assertEquals("200", results.get(0).get("status")); // User PUT
        assertEquals("200", results.get(1).get("status")); // Group PUT
        assertEquals("200", results.get(2).get("status")); // User PATCH
        assertEquals("200", results.get(3).get("status")); // Group PATCH
        assertEquals("204", results.get(4).get("status")); // User DELETE
        assertEquals("204", results.get(5).get("status")); // Group DELETE
        assertEquals("400", results.get(6).get("status")); // Invalid
    }

    @Test
    @SuppressWarnings("unchecked")
    void testProcessBulk_Errors() {
        // Invalid POST path
        Map<String, Object> opPostInvalid = Map.of("method", "POST", "path", "/Invalid", "data", Map.of());
        // Invalid PUT path (missing ID)
        Map<String, Object> opPutInvalid = Map.of("method", "PUT", "path", "/Users", "data", Map.of());

        Map<String, Object> body = Map.of(
                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"),
                "Operations", List.of(opPostInvalid, opPutInvalid));
        ResponseEntity<Map<String, Object>> response = controller.processBulk(workspaceId.toString(), body, null,
                request);

        List<Map<String, Object>> results = (List<Map<String, Object>>) response.getBody().get("Operations");
        assertEquals("400", results.get(0).get("status")); // User POST invalid path
        assertEquals("400", results.get(1).get("status")); // User PUT missing ID
    }

    // ─── Tests for Fix 3: failOnErrors stops processing ─────────────────

    @Test
    @SuppressWarnings("unchecked")
    void testProcessBulk_FailOnErrors_StopsProcessing() {
        // 3 POST operations to invalid paths (all will error), failOnErrors=2
        Map<String, Object> op1 = Map.of("method", "POST", "path", "/Invalid", "data", Map.of());
        Map<String, Object> op2 = Map.of("method", "POST", "path", "/Invalid", "data", Map.of());
        Map<String, Object> op3 = Map.of("method", "POST", "path", "/Invalid", "data", Map.of());

        Map<String, Object> body = new HashMap<>();
        body.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"));
        body.put("Operations", List.of(op1, op2, op3));
        body.put("failOnErrors", 2);

        ResponseEntity<Map<String, Object>> response = controller.processBulk(workspaceId.toString(), body, null, request);

        assertEquals(200, response.getStatusCode().value());
        List<Map<String, Object>> results = (List<Map<String, Object>>) response.getBody().get("Operations");
        // Should stop after 2 errors (op1 + op2), never process op3
        assertEquals(2, results.size());
        assertEquals("400", results.get(0).get("status"));
        assertEquals("400", results.get(1).get("status"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testProcessBulk_FailOnErrors_ZeroMeansNoLimit() {
        // failOnErrors=0 means process all operations regardless of errors
        Map<String, Object> op1 = Map.of("method", "POST", "path", "/Invalid", "data", Map.of());
        Map<String, Object> op2 = Map.of("method", "POST", "path", "/Invalid", "data", Map.of());

        Map<String, Object> body = new HashMap<>();
        body.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"));
        body.put("Operations", List.of(op1, op2));
        body.put("failOnErrors", 0);

        ResponseEntity<Map<String, Object>> response = controller.processBulk(workspaceId.toString(), body, null, request);

        List<Map<String, Object>> results = (List<Map<String, Object>>) response.getBody().get("Operations");
        assertEquals(2, results.size()); // All operations processed
    }

    // ─── Tests for Fix 4: BulkRequest schema validation ─────────────────

    @Test
    void testProcessBulk_MissingSchemasThrowsException() {
        Map<String, Object> body = new HashMap<>();
        body.put("Operations", List.of(Map.of("method", "POST", "path", "/Users", "data", Map.of())));
        // No "schemas" key at all

        String workspaceIdValue = workspaceId.toString();
        ScimException e = assertThrows(ScimException.class,
                () -> controller.processBulk(workspaceIdValue, body, null, request));
        assertTrue(e.getMessage().contains("BulkRequest schema"));
    }

    @Test
    void testProcessBulk_WrongSchemaThrowsException() {
        Map<String, Object> body = new HashMap<>();
        body.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"));
        body.put("Operations", List.of(Map.of("method", "POST", "path", "/Users", "data", Map.of())));

        String workspaceIdValue = workspaceId.toString();
        ScimException e = assertThrows(ScimException.class,
                () -> controller.processBulk(workspaceIdValue, body, null, request));
        assertTrue(e.getMessage().contains("BulkRequest schema"));
    }

    // ─── Tests for Fix 5: maxPayloadSize check ──────────────────────────

    @Test
    void testProcessBulk_ExceedsMaxPayloadSize_Throws413() {
        Map<String, Object> body = new HashMap<>();
        body.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"));
        body.put("Operations", List.of());

        // Set Content-Length to exceed 1MB
        request.addHeader("Content-Length", "2000000");
        request.setContentType("application/scim+json");
        request.setContent(new byte[2000000]);

        String workspaceIdValue = workspaceId.toString();
        ScimException e = assertThrows(ScimException.class,
                () -> controller.processBulk(workspaceIdValue, body, null, request));
        assertEquals(413, e.getHttpStatus());
        assertTrue(e.getMessage().contains("maxPayloadSize"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testProcessBulk_NonCanonicalPaths() {
        ScimUser user = new ScimUser();
        user.setId(UUID.randomUUID());
        when(userService.createUser(eq(workspaceId), any())).thenReturn(user);

        UUID userId = UUID.randomUUID();

        Map<String, Object> opDoubleSlash = Map.of(
                "method", "POST",
                "path", "//Users",
                "bulkId", "b1",
                "data", Map.of("userName", "doubleSlashUser"));

        Map<String, Object> opNoLeadingSlash = Map.of(
                "method", "POST",
                "path", "Users",
                "bulkId", "b2",
                "data", Map.of("userName", "noSlashUser"));

        Map<String, Object> opTrailingSlash = Map.of(
                "method", "POST",
                "path", "/Users/",
                "bulkId", "b3",
                "data", Map.of("userName", "trailingSlashUser"));

        Map<String, Object> opDeleteDoubleSlash = Map.of(
                "method", "DELETE",
                "path", "//Users/" + userId);

        Map<String, Object> body = Map.of(
                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"),
                "Operations", List.of(opDoubleSlash, opNoLeadingSlash, opTrailingSlash, opDeleteDoubleSlash));

        ResponseEntity<Map<String, Object>> response = controller.processBulk(workspaceId.toString(), body, null, request);

        assertEquals(200, response.getStatusCode().value());
        List<Map<String, Object>> results = (List<Map<String, Object>>) response.getBody().get("Operations");
        assertEquals(4, results.size());
        assertEquals("201", results.get(0).get("status"));
        assertEquals("201", results.get(1).get("status"));
        assertEquals("201", results.get(2).get("status"));
        assertEquals("204", results.get(3).get("status"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testProcessBulk_LowercaseUsersAndGroups() {
        UUID userId = UUID.randomUUID();
        UUID groupId = UUID.randomUUID();

        ScimUser user = new ScimUser();
        user.setId(userId);
        when(userService.replaceUser(eq(workspaceId), eq(userId), any(), any())).thenReturn(user);

        ScimGroup group = new ScimGroup();
        group.setId(groupId);
        when(groupService.patchGroup(eq(workspaceId), eq(groupId), any(), any())).thenReturn(group);

        Map<String, Object> opPut = Map.of(
                "method", "PUT",
                "path", "/users/" + userId,
                "data", Map.of("userName", "updatedUser"));

        Map<String, Object> opPatch = Map.of(
                "method", "PATCH",
                "path", "/groups/" + groupId,
                "data", Map.of("Operations", List.of(Map.of("op", "replace", "path", "displayName", "value", "newGroup"))));

        Map<String, Object> body = Map.of(
                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"),
                "Operations", List.of(opPut, opPatch));

        ResponseEntity<Map<String, Object>> response = controller.processBulk(workspaceId.toString(), body, null, request);

        assertEquals(200, response.getStatusCode().value());
        List<Map<String, Object>> results = (List<Map<String, Object>>) response.getBody().get("Operations");
        assertEquals(2, results.size());
        assertEquals("200", results.get(0).get("status"));
        assertEquals("200", results.get(1).get("status"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testProcessBulk_InvalidUUID_Returns400InvalidValue() {
        UUID validUuid = UUID.randomUUID();
        Map<String, Object> op1 = Map.of(
                "method", "DELETE",
                "path", "/Users/not-a-uuid");
        Map<String, Object> op2 = Map.of(
                "method", "DELETE",
                "path", "/Users/1-1-1-1-1");
        Map<String, Object> op3 = Map.of(
                "method", "DELETE",
                "path", "/Users/{" + validUuid + "}");
        Map<String, Object> op4 = Map.of(
                "method", "DELETE",
                "path", "/Users/urn:uuid:" + validUuid);
        Map<String, Object> op5 = Map.of(
                "method", "DELETE",
                "path", "/Users/000000001-0001-0001-0001-00000000001");
        Map<String, Object> op6 = Map.of(
                "method", "DELETE",
                "path", "/Users/+0000001-0001-0001-0001-000000000001");

        Map<String, Object> body = Map.of(
                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"),
                "Operations", List.of(op1, op2, op3, op4, op5, op6));

        ResponseEntity<Map<String, Object>> response = controller.processBulk(workspaceId.toString(), body, null, request);

        assertEquals(200, response.getStatusCode().value());
        List<Map<String, Object>> results = (List<Map<String, Object>>) response.getBody().get("Operations");
        assertEquals(6, results.size());

        for (int i = 0; i < 6; i++) {
            assertEquals("400", results.get(i).get("status"));
            Map<String, Object> resp = (Map<String, Object>) results.get(i).get("response");
            assertEquals("invalidValue", resp.get("scimType"));
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void testProcessBulk_UnknownResourceType_Returns400InvalidValue() {
        UUID id = UUID.randomUUID();
        Map<String, Object> op1 = Map.of(
                "method", "PUT",
                "path", "/UnknownEndpoint/" + id,
                "data", Map.of("userName", "test"));
        Map<String, Object> op2 = Map.of(
                "method", "DELETE",
                "path", "/InvalidResource/" + id);

        Map<String, Object> body = Map.of(
                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"),
                "Operations", List.of(op1, op2));

        ResponseEntity<Map<String, Object>> response = controller.processBulk(workspaceId.toString(), body, null, request);

        assertEquals(200, response.getStatusCode().value());
        List<Map<String, Object>> results = (List<Map<String, Object>>) response.getBody().get("Operations");
        assertEquals(2, results.size());

        assertEquals("400", results.get(0).get("status"));
        Map<String, Object> resp1 = (Map<String, Object>) results.get(0).get("response");
        assertEquals("invalidValue", resp1.get("scimType"));

        assertEquals("400", results.get(1).get("status"));
        Map<String, Object> resp2 = (Map<String, Object>) results.get(1).get("response");
        assertEquals("invalidValue", resp2.get("scimType"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testProcessBulk_PostItemPath_Returns400InvalidPath() {
        UUID id = UUID.randomUUID();
        Map<String, Object> op1 = Map.of(
                "method", "POST",
                "path", "/Users/" + id,
                "data", Map.of("userName", "test"));
        Map<String, Object> op2 = Map.of(
                "method", "POST",
                "path", "//Users//" + id,
                "data", Map.of("userName", "test"));

        Map<String, Object> body = Map.of(
                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"),
                "Operations", List.of(op1, op2));

        ResponseEntity<Map<String, Object>> response = controller.processBulk(workspaceId.toString(), body, null, request);

        assertEquals(200, response.getStatusCode().value());
        List<Map<String, Object>> results = (List<Map<String, Object>>) response.getBody().get("Operations");
        assertEquals(2, results.size());

        assertEquals("400", results.get(0).get("status"));
        Map<String, Object> resp1 = (Map<String, Object>) results.get(0).get("response");
        assertEquals("invalidPath", resp1.get("scimType"));

        assertEquals("400", results.get(1).get("status"));
        Map<String, Object> resp2 = (Map<String, Object>) results.get(1).get("response");
        assertEquals("invalidPath", resp2.get("scimType"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testProcessBulk_PathTraversal_Returns400InvalidPath() {
        UUID id = UUID.randomUUID();
        Map<String, Object> op1 = Map.of(
                "method", "POST",
                "path", "/Users/../Groups",
                "data", Map.of("displayName", "group"));
        Map<String, Object> op2 = Map.of(
                "method", "DELETE",
                "path", "/Users/../Groups/" + id);
        Map<String, Object> op3 = Map.of(
                "method", "DELETE",
                "path", "/Users/./" + id);

        Map<String, Object> body = Map.of(
                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"),
                "Operations", List.of(op1, op2, op3));

        ResponseEntity<Map<String, Object>> response = controller.processBulk(workspaceId.toString(), body, null, request);

        assertEquals(200, response.getStatusCode().value());
        List<Map<String, Object>> results = (List<Map<String, Object>>) response.getBody().get("Operations");
        assertEquals(3, results.size());

        assertEquals("400", results.get(0).get("status"));
        assertEquals("invalidPath", ((Map<String, Object>) results.get(0).get("response")).get("scimType"));

        assertEquals("400", results.get(1).get("status"));
        assertEquals("invalidPath", ((Map<String, Object>) results.get(1).get("response")).get("scimType"));

        assertEquals("400", results.get(2).get("status"));
        assertEquals("invalidPath", ((Map<String, Object>) results.get(2).get("response")).get("scimType"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testProcessBulk_PostMissingBulkId_Returns400OperationError() {
        // BLK_20: RFC 7644 §3.7 - The bulkId attribute is mandatory for 'POST' operations
        Map<String, Object> opNoBulkId = Map.of(
                "method", "POST",
                "path", "/Users",
                "data", Map.of("userName", "nobulkid@test.com")
        );

        Map<String, Object> body = Map.of(
                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"),
                "Operations", List.of(opNoBulkId)
        );

        ResponseEntity<Map<String, Object>> response = controller.processBulk(workspaceId.toString(), body, null, request);

        assertEquals(200, response.getStatusCode().value());
        List<Map<String, Object>> results = (List<Map<String, Object>>) response.getBody().get("Operations");
        assertEquals(1, results.size());

        Map<String, Object> opResult = results.get(0);
        assertEquals("400", opResult.get("status"));
        assertNull(opResult.get("bulkId"));

        Map<String, Object> errorResp = (Map<String, Object>) opResult.get("response");
        assertNotNull(errorResp);
        assertEquals("400", errorResp.get("status"));
        assertEquals("invalidValue", errorResp.get("scimType"));
        List<String> schemas = (List<String>) errorResp.get("schemas");
        assertTrue(schemas.contains("urn:ietf:params:scim:api:messages:2.0:Error"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testProcessBulk_MissingDataOnPostPutPatch_Returns400() {
        UUID userId = UUID.randomUUID();
        List<Map<String, Object>> ops = List.of(
                Map.of("method", "POST", "path", "/Users", "bulkId", "b1"),
                Map.of("method", "PUT", "path", "/Users/" + userId),
                Map.of("method", "PATCH", "path", "/Users/" + userId)
        );
        Map<String, Object> body = Map.of(
                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"),
                "Operations", ops);

        ResponseEntity<Map<String, Object>> response = controller.processBulk(workspaceId.toString(), body, null, request);
        List<Map<String, Object>> results = (List<Map<String, Object>>) response.getBody().get("Operations");
        assertEquals(3, results.size());
        assertEquals("400", results.get(0).get("status"));
        assertNull(results.get(0).get("location")); // failed POST omits location
        assertEquals("400", results.get(1).get("status"));
        assertTrue(((String) results.get(1).get("location")).endsWith("/Users/" + userId));
        assertEquals("400", results.get(2).get("status"));
        assertTrue(((String) results.get(2).get("location")).endsWith("/Users/" + userId));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testProcessBulk_VersionPreconditionAndDeleteLocation() {
        UUID userId = UUID.randomUUID();
        String staleVersion = "W/\"99\"";

        when(userService.replaceUser(eq(workspaceId), eq(userId), any(), eq(staleVersion)))
                .thenThrow(new ScimException(412, null, "Precondition failed"));
        when(userService.patchUser(eq(workspaceId), eq(userId), any(), eq(staleVersion)))
                .thenThrow(new ScimException(412, null, "Precondition failed"));
        Mockito.doThrow(new ScimException(412, null, "Precondition failed"))
                .when(userService).deleteUser(eq(workspaceId), eq(userId), eq(staleVersion));

        UUID delOkId = UUID.randomUUID();

        List<Map<String, Object>> ops = List.of(
                Map.of("method", "PUT", "path", "/Users/" + userId, "version", staleVersion, "data", Map.of("userName", "u")),
                Map.of("method", "PATCH", "path", "/Users/" + userId, "version", staleVersion,
                        "data", Map.of("Operations", List.of(Map.of("op", "replace", "path", "title", "value", "t")))),
                Map.of("method", "DELETE", "path", "/Users/" + userId, "version", staleVersion),
                Map.of("method", "DELETE", "path", "/Users/" + delOkId)
        );
        Map<String, Object> body = Map.of(
                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"),
                "Operations", ops);

        ResponseEntity<Map<String, Object>> response = controller.processBulk(workspaceId.toString(), body, null, request);
        List<Map<String, Object>> results = (List<Map<String, Object>>) response.getBody().get("Operations");
        assertEquals(4, results.size());

        for (int i = 0; i < 3; i++) {
            assertEquals("412", results.get(i).get("status"));
            assertTrue(((String) results.get(i).get("location")).endsWith("/Users/" + userId));
        }
        assertEquals("204", results.get(3).get("status"));
        assertTrue(((String) results.get(3).get("location")).endsWith("/Users/" + delOkId));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testProcessBulk_ForwardBulkIdDependency_PreservesOriginalResponseOrder() {
        UUID createdUserId = UUID.randomUUID();
        UUID createdGroupId = UUID.randomUUID();

        ScimUser createdUser = new ScimUser();
        createdUser.setId(createdUserId);
        createdUser.setVersion(0L);
        when(userService.createUser(eq(workspaceId), any())).thenReturn(createdUser);

        ScimGroup createdGroup = new ScimGroup();
        createdGroup.setId(createdGroupId);
        createdGroup.setVersion(0L);
        when(groupService.createGroup(eq(workspaceId), argThat(data -> {
            if (data == null) return false;
            List<Map<String, Object>> members = (List<Map<String, Object>>) data.get("members");
            return members != null && members.size() == 1
                    && createdUserId.toString().equals(members.get(0).get("value"));
        }))).thenReturn(createdGroup);

        // Group at index 0 references User created later at index 1
        Map<String, Object> opGroupFirst = Map.of(
                "method", "POST",
                "path", "/Groups",
                "bulkId", "grp1",
                "data", Map.of("displayName", "ForwardGroup",
                        "members", List.of(Map.of("value", "bulkId:usr1", "type", "User")))
        );
        Map<String, Object> opUserSecond = Map.of(
                "method", "POST",
                "path", "/Users",
                "bulkId", "usr1",
                "data", Map.of("userName", "forwardUser")
        );

        Map<String, Object> body = Map.of(
                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"),
                "Operations", List.of(opGroupFirst, opUserSecond));

        ResponseEntity<Map<String, Object>> response = controller.processBulk(workspaceId.toString(), body, null, request);
        List<Map<String, Object>> results = (List<Map<String, Object>>) response.getBody().get("Operations");
        assertEquals(2, results.size());
        assertEquals("grp1", results.get(0).get("bulkId"));
        assertEquals("201", results.get(0).get("status"));
        assertTrue(((String) results.get(0).get("location")).endsWith("/Groups/" + createdGroupId));

        assertEquals("usr1", results.get(1).get("bulkId"));
        assertEquals("201", results.get(1).get("status"));
        assertTrue(((String) results.get(1).get("location")).endsWith("/Users/" + createdUserId));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testProcessBulk_CircularGroupBulkIds_TwoPassResolution() {
        UUID groupAId = UUID.randomUUID();
        UUID groupBId = UUID.randomUUID();

        ScimGroup groupA = new ScimGroup();
        groupA.setId(groupAId);
        groupA.setVersion(0L);

        ScimGroup groupB = new ScimGroup();
        groupB.setId(groupBId);
        groupB.setVersion(0L);

        when(groupService.createGroup(eq(workspaceId), argThat(d -> d != null && "GroupA".equals(d.get("displayName")) && !d.containsKey("members"))))
                .thenReturn(groupA);
        when(groupService.createGroup(eq(workspaceId), argThat(d -> d != null && "GroupB".equals(d.get("displayName")) && !d.containsKey("members"))))
                .thenReturn(groupB);

        ScimGroup patchedA = new ScimGroup();
        patchedA.setId(groupAId);
        patchedA.setVersion(1L);
        ScimGroup patchedB = new ScimGroup();
        patchedB.setId(groupBId);
        patchedB.setVersion(1L);

        when(groupService.patchGroup(eq(workspaceId), eq(groupAId), any(), isNull())).thenReturn(patchedA);
        when(groupService.patchGroup(eq(workspaceId), eq(groupBId), any(), isNull())).thenReturn(patchedB);

        Map<String, Object> opA = Map.of(
                "method", "POST",
                "path", "/Groups",
                "bulkId", "qwerty",
                "data", Map.of("displayName", "GroupA",
                        "members", List.of(Map.of("type", "Group", "value", "bulkId:ytrewq")))
        );
        Map<String, Object> opB = Map.of(
                "method", "POST",
                "path", "/Groups",
                "bulkId", "ytrewq",
                "data", Map.of("displayName", "GroupB",
                        "members", List.of(Map.of("type", "Group", "value", "bulkId:qwerty")))
        );

        Map<String, Object> body = Map.of(
                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"),
                "Operations", List.of(opA, opB));

        ResponseEntity<Map<String, Object>> response = controller.processBulk(workspaceId.toString(), body, null, request);
        List<Map<String, Object>> results = (List<Map<String, Object>>) response.getBody().get("Operations");
        assertEquals(2, results.size());
        assertEquals("201", results.get(0).get("status"));
        assertEquals("qwerty", results.get(0).get("bulkId"));
        assertEquals("W/\"1\"", results.get(0).get("version"));
        assertEquals("201", results.get(1).get("status"));
        assertEquals("ytrewq", results.get(1).get("bulkId"));
        assertEquals("W/\"1\"", results.get(1).get("version"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testProcessBulk_CircularGroupPass2PatchValidationFailure_DeletesShellsAndPreservesScimError() {
        UUID groupAId = UUID.randomUUID();
        UUID groupBId = UUID.randomUUID();

        ScimGroup groupA = new ScimGroup();
        groupA.setId(groupAId);
        groupA.setVersion(0L);

        ScimGroup groupB = new ScimGroup();
        groupB.setId(groupBId);
        groupB.setVersion(0L);

        when(groupService.createGroup(eq(workspaceId), argThat(d -> d != null && "GroupA".equals(d.get("displayName")))))
                .thenReturn(groupA);
        when(groupService.createGroup(eq(workspaceId), argThat(d -> d != null && "GroupB".equals(d.get("displayName")))))
                .thenReturn(groupB);

        ScimGroup patchedA = new ScimGroup();
        patchedA.setId(groupAId);
        patchedA.setVersion(1L);
        when(groupService.patchGroup(eq(workspaceId), eq(groupAId), any(), isNull())).thenReturn(patchedA);
        when(groupService.patchGroup(eq(workspaceId), eq(groupBId), any(), isNull()))
                .thenThrow(new ScimException(400, "invalidValue", "Unsupported member type"));

        Map<String, Object> opA = Map.of(
                "method", "POST",
                "path", "/Groups",
                "bulkId", "gA",
                "data", Map.of("displayName", "GroupA",
                        "members", List.of(Map.of("type", "Group", "value", "bulkId:gB")))
        );
        Map<String, Object> opB = Map.of(
                "method", "POST",
                "path", "/Groups",
                "bulkId", "gB",
                "data", Map.of("displayName", "GroupB",
                        "members", List.of(Map.of("type", "InvalidType", "value", "bulkId:gA")))
        );
        // Downstream operation referencing failed bulkId:gB must not resolve to the deleted UUID
        Map<String, Object> opDownstream = Map.of(
                "method", "DELETE",
                "path", "/Groups/bulkId:gB"
        );

        Map<String, Object> body = Map.of(
                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"),
                "Operations", List.of(opA, opB, opDownstream));

        ResponseEntity<Map<String, Object>> response = controller.processBulk(workspaceId.toString(), body, null, request);
        List<Map<String, Object>> results = (List<Map<String, Object>>) response.getBody().get("Operations");
        assertEquals(3, results.size());

        // GroupB failed with 400 invalidValue (preserved, not overwritten with 409) and its shell was deleted
        assertEquals("400", results.get(1).get("status"));
        assertNull(results.get(1).get("location"));
        Map<String, Object> errB = (Map<String, Object>) results.get(1).get("response");
        assertEquals("invalidValue", errB.get("scimType"));
        Mockito.verify(groupService).deleteGroup(workspaceId, groupBId);

        // GroupA depended on gB, so its shell is also compensated and marked 409
        assertEquals("409", results.get(0).get("status"));
        assertNull(results.get(0).get("location"));
        Mockito.verify(groupService).deleteGroup(workspaceId, groupAId);

        // Downstream DELETE did not resolve bulkId:gB to groupBId
        assertEquals("400", results.get(2).get("status"));
        Mockito.verify(groupService, Mockito.never()).deleteGroup(eq(workspaceId), eq(groupBId), any());
    }

    @Test
    @SuppressWarnings("unchecked")
    void testProcessBulk_CircularUserFailOnErrorsMidPass1_CompensatesShellInsteadOfReturningUnpatched201() {
        String entUrn = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
        UUID userAId = UUID.randomUUID();
        ScimUser userA = new ScimUser();
        userA.setId(userAId);
        userA.setVersion(0L);

        when(userService.createUser(eq(workspaceId), argThat(d -> d != null && "alice".equals(d.get("userName")))))
                .thenReturn(userA);
        when(userService.createUser(eq(workspaceId), argThat(d -> d != null && "bob".equals(d.get("userName")))))
                .thenThrow(new ScimException(409, "uniqueness", "userName already exists"));

        Map<String, Object> opA = Map.of(
                "method", "POST",
                "path", "/Users",
                "bulkId", "uA",
                "data", Map.of(
                        "userName", "alice",
                        entUrn, Map.of("manager", Map.of("value", "bulkId:uB")))
        );
        Map<String, Object> opB = Map.of(
                "method", "POST",
                "path", "/Users",
                "bulkId", "uB",
                "data", Map.of(
                        "userName", "bob",
                        entUrn, Map.of("manager", Map.of("value", "bulkId:uC")))
        );
        Map<String, Object> opC = Map.of(
                "method", "POST",
                "path", "/Users",
                "bulkId", "uC",
                "data", Map.of(
                        "userName", "carol",
                        entUrn, Map.of("manager", Map.of("value", "bulkId:uA")))
        );

        Map<String, Object> body = Map.of(
                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkRequest"),
                "failOnErrors", 1,
                "Operations", List.of(opA, opB, opC));

        ResponseEntity<Map<String, Object>> response = controller.processBulk(workspaceId.toString(), body, null, request);
        List<Map<String, Object>> results = (List<Map<String, Object>>) response.getBody().get("Operations");

        // opC was skipped after opB hit failOnErrors=1, and opA's shell was compensated (not left as unpatched 201!)
        assertEquals(2, results.size());
        assertEquals("uA", results.get(0).get("bulkId"));
        assertEquals("409", results.get(0).get("status"));
        assertNull(results.get(0).get("location"));
        Mockito.verify(userService).deleteUser(workspaceId, userAId);

        assertEquals("uB", results.get(1).get("bulkId"));
        assertEquals("409", results.get(1).get("status"));
        Mockito.verify(userService, Mockito.never()).createUser(
                eq(workspaceId), argThat(d -> d != null && "carol".equals(d.get("userName"))));
    }
}
