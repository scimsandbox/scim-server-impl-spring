package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.service.ScimUserService;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

class ScimUserControllerTest {

    private ScimUserService userService;
    private ScimUserController controller;
    private ScimUser mockUser;
    private final UUID workspaceId = UUID.randomUUID();
    private final UUID userId = UUID.randomUUID();
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        userService = Mockito.mock(ScimUserService.class);
        controller = new ScimUserController(userService);

        mockUser = new ScimUser();
        mockUser.setId(userId);
        mockUser.setUserName("test.user");
        mockUser.setVersion(1L);
        mockUser.setCreatedAt(Instant.now());
        mockUser.setLastModified(Instant.now());

        request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("localhost");
        request.setServerPort(8080);
        request.setRequestURI("/ws/" + workspaceId + "/scim/v2/Users");
    }

    @Test
    void testCreateUser() {
        when(userService.createUser(eq(workspaceId), any())).thenReturn(mockUser);
        when(userService.getUserGroups(any(), any())).thenReturn(Collections.emptyList());

        Map<String, Object> body = Map.of("userName", "test.user");
        ResponseEntity<Map<String, Object>> response = controller.createUser(workspaceId.toString(), body, null, request);

        assertEquals(201, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertEquals("test.user", response.getBody().get("userName"));
        
        // Test compat branch MS
        response = controller.createUser(workspaceId.toString(), body, "entra", request);
        assertEquals(201, response.getStatusCode().value());
    }

    @Test
    void testGetUser() {
        when(userService.getUser(workspaceId, userId)).thenReturn(mockUser);
        when(userService.getUserGroups(any(), any())).thenReturn(Collections.emptyList());

        ResponseEntity<Map<String, Object>> response = controller.getUser(workspaceId.toString(), userId.toString(), null, null, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertEquals("test.user", response.getBody().get("userName"));
        
        // With projection
        response = controller.getUser(workspaceId.toString(), userId.toString(), "userName", null, null, null, request);
        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    @SuppressWarnings("unchecked")
    void testListUsers() {
        Map<String, Object> result = new HashMap<>();
        result.put("Resources", List.of(mockUser));
        
        when(userService.listUsers(eq(workspaceId), any(), any(), any(), anyInt(), anyInt())).thenReturn(result);
        when(userService.getUserGroupsBatch(any(), any())).thenReturn(Collections.emptyMap());

        ResponseEntity<Map<String, Object>> response = controller.listUsers(workspaceId.toString(), null, "userName", "ascending", -1, 300, null, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        List<Map<String, Object>> resources = (List<Map<String, Object>>) response.getBody().get("Resources");
        assertEquals(1, resources.size());
        assertEquals("test.user", resources.get(0).get("userName"));
    }

    @Test
    void testReplaceUser() {
        when(userService.replaceUser(eq(workspaceId), eq(userId), any(), any())).thenReturn(mockUser);
        when(userService.getUserGroups(any(), any())).thenReturn(Collections.emptyList());

        Map<String, Object> body = Map.of("userName", "test.user");
        ResponseEntity<Map<String, Object>> response = controller.replaceUser(workspaceId.toString(), userId.toString(), body, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertEquals("test.user", response.getBody().get("userName"));
    }

    @Test
    void testPatchUser() {
        when(userService.patchUser(eq(workspaceId), eq(userId), any(), any())).thenReturn(mockUser);
        when(userService.getUserGroups(any(), any())).thenReturn(Collections.emptyList());

        Map<String, Object> body = new HashMap<>();
        body.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"));
        body.put("Operations", List.of(Map.of("op", "replace", "path", "userName", "value", "updated")));

        ResponseEntity<Map<String, Object>> response = controller.patchUser(workspaceId.toString(), userId.toString(), body, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        assertEquals("test.user", response.getBody().get("userName"));
    }

    @Test
    void testPatchUser_Exception() {
        String workspaceIdValue = workspaceId.toString();
        String userIdValue = userId.toString();

        Map<String, Object> bodyMissingSchema = new HashMap<>();
        assertThrows(ScimException.class, () -> controller.patchUser(workspaceIdValue, userIdValue, bodyMissingSchema, null, null, request));

        Map<String, Object> bodyMissingOps = new HashMap<>();
        bodyMissingOps.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"));
        assertThrows(ScimException.class, () -> controller.patchUser(workspaceIdValue, userIdValue, bodyMissingOps, null, null, request));
    }

    @Test
    void testDeleteUser() {
        Mockito.doNothing().when(userService).deleteUser(workspaceId, userId);

        ResponseEntity<Void> response = controller.deleteUser(workspaceId.toString(), userId.toString(), null);

        assertEquals(204, response.getStatusCode().value());
    }

    // ─── Tests for Fix 1: POST /.search ─────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void testSearchUsers() {
        Map<String, Object> result = new HashMap<>();
        result.put("Resources", List.of(mockUser));

        when(userService.listUsers(eq(workspaceId), any(), any(), any(), anyInt(), anyInt())).thenReturn(result);
        when(userService.getUserGroupsBatch(any(), any())).thenReturn(Collections.emptyMap());

        Map<String, Object> body = new HashMap<>();
        body.put("filter", "userName eq \"test.user\"");
        body.put("sortBy", "userName");
        body.put("sortOrder", "ascending");
        body.put("startIndex", 1);
        body.put("count", 10);

        ResponseEntity<Map<String, Object>> response = controller.searchUsers(workspaceId.toString(), body, null, request);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        List<Map<String, Object>> resources = (List<Map<String, Object>>) response.getBody().get("Resources");
        assertEquals(1, resources.size());
    }

    @Test
    void testSearchUsersDefaults() {
        Map<String, Object> result = new HashMap<>();
        result.put("Resources", List.of(mockUser));

        when(userService.listUsers(eq(workspaceId), any(), any(), any(), anyInt(), anyInt())).thenReturn(result);
        when(userService.getUserGroupsBatch(any(), any())).thenReturn(Collections.emptyMap());

        // Empty body — should use defaults
        Map<String, Object> body = new HashMap<>();

        ResponseEntity<Map<String, Object>> response = controller.searchUsers(workspaceId.toString(), body, null, request);

        assertEquals(200, response.getStatusCode().value());
    }

    // ─── Tests for Fix 7: If-None-Match / 304 ──────────────────────────

    @Test
    void testGetUser_IfNoneMatch_ReturnsNotModified() {
        when(userService.getUser(workspaceId, userId)).thenReturn(mockUser);

        String etag = "W/\"" + mockUser.getVersion() + "\"";
        ResponseEntity<Map<String, Object>> response = controller.getUser(
                workspaceId.toString(), userId.toString(), null, null, etag, null, request);

        assertEquals(304, response.getStatusCode().value());
        assertNull(response.getBody());
    }

    @Test
    void testGetUser_IfNoneMatch_Wildcard_ReturnsNotModified() {
        when(userService.getUser(workspaceId, userId)).thenReturn(mockUser);

        ResponseEntity<Map<String, Object>> response = controller.getUser(
                workspaceId.toString(), userId.toString(), null, null, "*", null, request);

        assertEquals(304, response.getStatusCode().value());
        assertNull(response.getBody());
    }

    @Test
    void testGetUser_IfNoneMatch_Mismatch_Returns200() {
        when(userService.getUser(workspaceId, userId)).thenReturn(mockUser);
        when(userService.getUserGroups(any(), any())).thenReturn(Collections.emptyList());

        ResponseEntity<Map<String, Object>> response = controller.getUser(
                workspaceId.toString(), userId.toString(), null, null, "W/\"999\"", null, request);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
    }

    // ─── Tests for Fix 9: Content-Location header ───────────────────────

    @Test
    void testCreateUser_HasContentLocationHeader() {
        when(userService.createUser(eq(workspaceId), any())).thenReturn(mockUser);
        when(userService.getUserGroups(any(), any())).thenReturn(Collections.emptyList());

        Map<String, Object> body = Map.of("userName", "test.user");
        ResponseEntity<Map<String, Object>> response = controller.createUser(workspaceId.toString(), body, null, request);

        assertEquals(201, response.getStatusCode().value());
        assertNotNull(response.getHeaders().getFirst("Content-Location"));
        assertTrue(response.getHeaders().getFirst("Content-Location").contains(userId.toString()));
    }

    @Test
    void testGetUser_HasContentLocationHeader() {
        when(userService.getUser(workspaceId, userId)).thenReturn(mockUser);
        when(userService.getUserGroups(any(), any())).thenReturn(Collections.emptyList());

        ResponseEntity<Map<String, Object>> response = controller.getUser(
                workspaceId.toString(), userId.toString(), null, null, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getHeaders().getFirst("Content-Location"));
        assertTrue(response.getHeaders().getFirst("Content-Location").contains("/Users/" + userId));
    }

    @Test
    void testReplaceUser_HasContentLocationHeader() {
        when(userService.replaceUser(eq(workspaceId), eq(userId), any(), any())).thenReturn(mockUser);
        when(userService.getUserGroups(any(), any())).thenReturn(Collections.emptyList());

        Map<String, Object> body = Map.of("userName", "test.user");
        ResponseEntity<Map<String, Object>> response = controller.replaceUser(workspaceId.toString(), userId.toString(), body, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getHeaders().getFirst("Content-Location"));
        assertTrue(response.getHeaders().getFirst("Content-Location").contains("/Users/" + userId));
    }

    @Test
    void testPatchUser_HasContentLocationHeader() {
        when(userService.patchUser(eq(workspaceId), eq(userId), any(), any())).thenReturn(mockUser);
        when(userService.getUserGroups(any(), any())).thenReturn(Collections.emptyList());

        Map<String, Object> body = new HashMap<>();
        body.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"));
        body.put("Operations", List.of(Map.of("op", "replace", "path", "userName", "value", "updated")));

        ResponseEntity<Map<String, Object>> response = controller.patchUser(workspaceId.toString(), userId.toString(), body, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getHeaders().getFirst("Content-Location"));
        assertTrue(response.getHeaders().getFirst("Content-Location").contains("/Users/" + userId));
    }

    // ─── Tests for Fix 8: password never returned ───────────────────────

    @Test
    void testGetUser_PasswordRemovedFromProjection() {
        mockUser.setPassword("secret123");
        when(userService.getUser(workspaceId, userId)).thenReturn(mockUser);
        when(userService.getUserGroups(any(), any())).thenReturn(Collections.emptyList());

        ResponseEntity<Map<String, Object>> response = controller.getUser(
                workspaceId.toString(), userId.toString(), "userName", null, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        assertFalse(response.getBody().containsKey("password"));
    }

    // ─── Tests for Fix 10: URN-prefixed attribute projection ────────────

    @Test
    void testGetUser_UrnPrefixedCoreAttribute() {
        when(userService.getUser(workspaceId, userId)).thenReturn(mockUser);
        when(userService.getUserGroups(any(), any())).thenReturn(Collections.emptyList());

        // Use urn:ietf:params:scim:schemas:core:2.0:User:userName — should resolve to "userName"
        ResponseEntity<Map<String, Object>> response = controller.getUser(
                workspaceId.toString(), userId.toString(),
                "urn:ietf:params:scim:schemas:core:2.0:User:userName", null, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        assertTrue(response.getBody().containsKey("userName"));
        // Should only contain schemas, id, meta, and userName (projected attributes + always-returned)
        assertFalse(response.getBody().containsKey("displayName"));
    }

    @Test
    void testGetUser_UrnPrefixedEnterpriseExtension() {
        when(userService.getUser(workspaceId, userId)).thenReturn(mockUser);
        when(userService.getUserGroups(any(), any())).thenReturn(Collections.emptyList());

        // Enterprise URN should be kept as the top-level key
        ResponseEntity<Map<String, Object>> response = controller.getUser(
                workspaceId.toString(), userId.toString(),
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber", null, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        // The enterprise URN key should be retained (if it existed in the response)
        // At minimum, schemas, id, meta should be present
        assertTrue(response.getBody().containsKey("schemas"));
        assertTrue(response.getBody().containsKey("id"));
    }
}
