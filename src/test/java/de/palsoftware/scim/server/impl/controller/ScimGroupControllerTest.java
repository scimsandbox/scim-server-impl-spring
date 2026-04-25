package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.service.ScimGroupService;
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

class ScimGroupControllerTest {

    private static final String TEST_GROUP = "Test Group";
    private static final String DISPLAY_NAME = "displayName";

    private ScimGroupService groupService;
    private ScimGroupController controller;
    private ScimGroup mockGroup;
    private final UUID workspaceId = UUID.randomUUID();
    private final UUID groupId = UUID.randomUUID();
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        groupService = Mockito.mock(ScimGroupService.class);
        controller = new ScimGroupController(groupService);

        mockGroup = new ScimGroup();
        mockGroup.setId(groupId);
        mockGroup.setDisplayName(TEST_GROUP);
        mockGroup.setVersion(1L);
        mockGroup.setCreatedAt(Instant.now());
        mockGroup.setLastModified(Instant.now());

        request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("localhost");
        request.setServerPort(8080);
        request.setRequestURI("/ws/" + workspaceId + "/scim/v2/Groups");
    }

    @Test
    void createGroupReturnsCreated() {
        when(groupService.createGroup(eq(workspaceId), any())).thenReturn(mockGroup);

        Map<String, Object> body = Map.of(DISPLAY_NAME, TEST_GROUP);
        ResponseEntity<Map<String, Object>> response = controller.createGroup(workspaceId.toString(), body, null, request);

        assertEquals(201, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertEquals(TEST_GROUP, response.getBody().get(DISPLAY_NAME));
    }

    @Test
    void getGroupReturnsResource() {
        when(groupService.getGroup(workspaceId, groupId)).thenReturn(mockGroup);

        ResponseEntity<Map<String, Object>> response = controller.getGroup(workspaceId.toString(), groupId.toString(), null, null, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertEquals(TEST_GROUP, response.getBody().get(DISPLAY_NAME));
        
        response = controller.getGroup(workspaceId.toString(), groupId.toString(), DISPLAY_NAME, null, null, null, request);
        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    @SuppressWarnings("unchecked")
    void listGroupsReturnsPagedResource() {
        Map<String, Object> result = new HashMap<>();
        result.put("Resources", List.of(mockGroup));
        
        when(groupService.listGroups(eq(workspaceId), any(), any(), any(), anyInt(), anyInt())).thenReturn(result);

        ResponseEntity<Map<String, Object>> response = controller.listGroups(workspaceId.toString(), null, DISPLAY_NAME, "ascending", -1, 300, null, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        List<Map<String, Object>> resources = (List<Map<String, Object>>) response.getBody().get("Resources");
        assertEquals(1, resources.size());
        assertEquals(TEST_GROUP, resources.get(0).get(DISPLAY_NAME));
    }

    @Test
    void replaceGroupReturnsUpdatedResource() {
        when(groupService.replaceGroup(eq(workspaceId), eq(groupId), any(), any())).thenReturn(mockGroup);

        Map<String, Object> body = Map.of(DISPLAY_NAME, TEST_GROUP);
        ResponseEntity<Map<String, Object>> response = controller.replaceGroup(workspaceId.toString(), groupId.toString(), body, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertEquals(TEST_GROUP, response.getBody().get(DISPLAY_NAME));
    }

    @Test
    void patchGroupReturnsUpdatedResource() {
        when(groupService.patchGroup(eq(workspaceId), eq(groupId), any(), any())).thenReturn(mockGroup);

        Map<String, Object> body = new HashMap<>();
        body.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"));
        body.put("Operations", List.of(Map.of("op", "replace", "path", DISPLAY_NAME, "value", "updated")));

        ResponseEntity<Map<String, Object>> response = controller.patchGroup(workspaceId.toString(), groupId.toString(), body, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        assertEquals(TEST_GROUP, response.getBody().get(DISPLAY_NAME));
    }

    @Test
    void patchGroupValidatesInput() {
        String workspaceIdValue = workspaceId.toString();
        String groupIdValue = groupId.toString();

        Map<String, Object> bodyMissingSchema = new HashMap<>();
        assertThrows(ScimException.class, () -> controller.patchGroup(workspaceIdValue, groupIdValue, bodyMissingSchema, null, null, request));

        Map<String, Object> bodyMissingOps = new HashMap<>();
        bodyMissingOps.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"));
        assertThrows(ScimException.class, () -> controller.patchGroup(workspaceIdValue, groupIdValue, bodyMissingOps, null, null, request));
    }

    @Test
    void deleteGroupReturnsNoContent() {
        Mockito.doNothing().when(groupService).deleteGroup(workspaceId, groupId);

        ResponseEntity<Void> response = controller.deleteGroup(workspaceId.toString(), groupId.toString(), null);

        assertEquals(204, response.getStatusCode().value());
    }

    // ─── Tests for Fix 1: POST /.search ─────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void searchGroupsReturnsResults() {
        Map<String, Object> result = new HashMap<>();
        result.put("Resources", List.of(mockGroup));

        when(groupService.listGroups(eq(workspaceId), any(), any(), any(), anyInt(), anyInt())).thenReturn(result);

        Map<String, Object> body = new HashMap<>();
        body.put("filter", "displayName eq \"Test Group\"");
        body.put("sortBy", DISPLAY_NAME);
        body.put("sortOrder", "ascending");
        body.put("startIndex", 1);
        body.put("count", 10);

        ResponseEntity<Map<String, Object>> response = controller.searchGroups(workspaceId.toString(), body, null, request);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        List<Map<String, Object>> resources = (List<Map<String, Object>>) response.getBody().get("Resources");
        assertEquals(1, resources.size());
    }

    @Test
    void searchGroupsUsesDefaults() {
        Map<String, Object> result = new HashMap<>();
        result.put("Resources", List.of(mockGroup));

        when(groupService.listGroups(eq(workspaceId), any(), any(), any(), anyInt(), anyInt())).thenReturn(result);

        // Empty body — should use defaults
        Map<String, Object> body = new HashMap<>();

        ResponseEntity<Map<String, Object>> response = controller.searchGroups(workspaceId.toString(), body, null, request);

        assertEquals(200, response.getStatusCode().value());
    }

    // ─── Tests for Fix 7: If-None-Match / 304 ──────────────────────────

    @Test
    void getGroupIfNoneMatchReturnsNotModified() {
        when(groupService.getGroup(workspaceId, groupId)).thenReturn(mockGroup);

        String etag = "W/\"" + mockGroup.getVersion() + "\"";
        ResponseEntity<Map<String, Object>> response = controller.getGroup(
                workspaceId.toString(), groupId.toString(), null, null, etag, null, request);

        assertEquals(304, response.getStatusCode().value());
        assertNull(response.getBody());
    }

    @Test
    void getGroupIfNoneMatchWildcardReturnsNotModified() {
        when(groupService.getGroup(workspaceId, groupId)).thenReturn(mockGroup);

        ResponseEntity<Map<String, Object>> response = controller.getGroup(
                workspaceId.toString(), groupId.toString(), null, null, "*", null, request);

        assertEquals(304, response.getStatusCode().value());
        assertNull(response.getBody());
    }

    @Test
    void getGroupIfNoneMatchMismatchReturns200() {
        when(groupService.getGroup(workspaceId, groupId)).thenReturn(mockGroup);

        ResponseEntity<Map<String, Object>> response = controller.getGroup(
                workspaceId.toString(), groupId.toString(), null, null, "W/\"999\"", null, request);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
    }

    // ─── Tests for Fix 9: Content-Location header ───────────────────────

    @Test
    void createGroupHasContentLocationHeader() {
        when(groupService.createGroup(eq(workspaceId), any())).thenReturn(mockGroup);

        Map<String, Object> body = Map.of(DISPLAY_NAME, TEST_GROUP);
        ResponseEntity<Map<String, Object>> response = controller.createGroup(workspaceId.toString(), body, null, request);

        assertEquals(201, response.getStatusCode().value());
        assertNotNull(response.getHeaders().getFirst("Content-Location"));
        assertTrue(response.getHeaders().getFirst("Content-Location").contains(groupId.toString()));
    }

    @Test
    void getGroupHasContentLocationHeader() {
        when(groupService.getGroup(workspaceId, groupId)).thenReturn(mockGroup);

        ResponseEntity<Map<String, Object>> response = controller.getGroup(
                workspaceId.toString(), groupId.toString(), null, null, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getHeaders().getFirst("Content-Location"));
        assertTrue(response.getHeaders().getFirst("Content-Location").contains("/Groups/" + groupId));
    }

    @Test
    void replaceGroupHasContentLocationHeader() {
        when(groupService.replaceGroup(eq(workspaceId), eq(groupId), any(), any())).thenReturn(mockGroup);

        Map<String, Object> body = Map.of(DISPLAY_NAME, TEST_GROUP);
        ResponseEntity<Map<String, Object>> response = controller.replaceGroup(workspaceId.toString(), groupId.toString(), body, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getHeaders().getFirst("Content-Location"));
        assertTrue(response.getHeaders().getFirst("Content-Location").contains("/Groups/" + groupId));
    }

    @Test
    void patchGroupHasContentLocationHeader() {
        when(groupService.patchGroup(eq(workspaceId), eq(groupId), any(), any())).thenReturn(mockGroup);

        Map<String, Object> body = new HashMap<>();
        body.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"));
        body.put("Operations", List.of(Map.of("op", "replace", "path", DISPLAY_NAME, "value", "updated")));

        ResponseEntity<Map<String, Object>> response = controller.patchGroup(workspaceId.toString(), groupId.toString(), body, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getHeaders().getFirst("Content-Location"));
        assertTrue(response.getHeaders().getFirst("Content-Location").contains("/Groups/" + groupId));
    }
}
