package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.service.ScimGroupService;
import de.palsoftware.scim.server.impl.service.ScimUserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

class ScimDiscoveryControllerTest {

    private ScimUserService userService;
    private ScimGroupService groupService;
    private ScimDiscoveryController controller;
    private MockHttpServletRequest request;
    private final String workspaceId = "24fb7ccb-3458-44da-b5c8-92b97e2ad702";
    private final UUID wsUuid = UUID.fromString(workspaceId);

    @BeforeEach
    void setUp() {
        userService = Mockito.mock(ScimUserService.class);
        groupService = Mockito.mock(ScimGroupService.class);
        controller = new ScimDiscoveryController(userService, groupService);
        request = new MockHttpServletRequest();
        request.setServerName("localhost");
        request.setServerPort(8080);
        request.setScheme("http");
    }

    @Test
    void getServiceProviderConfigReturns200() {
        ResponseEntity<Map<String, Object>> response = controller.getServiceProviderConfig(null);
        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().containsKey("schemas"));
        Map<?, ?> changePassword = (Map<?, ?>) response.getBody().get("changePassword");
        assertNotNull(changePassword);
        assertEquals(true, changePassword.get("supported"));
    }

    @Test
    void getSchemasReturns200() {
        ResponseEntity<Map<String, Object>> response = controller.getSchemas(null);
        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertEquals(List.of("urn:ietf:params:scim:api:messages:2.0:ListResponse"), response.getBody().get("schemas"));
    }

    @Test
    void getSchemaByIdNotFoundThrows404() {
        assertThrows(ScimException.class, () -> controller.getSchemaById("unknown-schema", null));
    }

    private ScimUser createMockUser(String userName) {
        ScimUser user = new ScimUser();
        user.setId(UUID.randomUUID());
        user.setUserName(userName);
        user.setCreatedAt(java.time.Instant.now());
        user.setLastModified(java.time.Instant.now());
        user.setVersion(1L);
        return user;
    }

    private ScimGroup createMockGroup(String displayName) {
        ScimGroup group = new ScimGroup();
        group.setId(UUID.randomUUID());
        group.setDisplayName(displayName);
        group.setCreatedAt(java.time.Instant.now());
        group.setLastModified(java.time.Instant.now());
        group.setVersion(1L);
        return group;
    }

    @Test
    void rootSearchGetUsersOnlyReturns200() {
        ScimUser user = createMockUser("alice");

        Map<String, Object> userCountResult = Map.of("totalResults", 1L, "Resources", Collections.emptyList());
        Map<String, Object> userPageResult = Map.of("totalResults", 1L, "Resources", List.of(user));

        when(userService.listUsers(eq(wsUuid), anyString(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(userCountResult);
        when(userService.listUsers(eq(wsUuid), anyString(), eq("userName"), eq("ascending"), eq(1), eq(100)))
                .thenReturn(userPageResult);
        when(userService.getUserGroupsBatch(anyList(), anyString()))
                .thenReturn(Collections.emptyMap());

        ResponseEntity<Map<String, Object>> response = controller.rootSearchGet(
                workspaceId, "meta.resourceType eq \"User\"", 1, 100, "userName", "ascending",
                null, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        Map<String, Object> body = response.getBody();
        assertNotNull(body);
        assertEquals(1L, body.get("totalResults"));
        assertEquals(1, body.get("itemsPerPage"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> resources = (List<Map<String, Object>>) body.get("Resources");
        assertEquals(1, resources.size());
        assertEquals("alice", resources.get(0).get("userName"));
    }

    @Test
    void rootSearchGetGroupsOnlyReturns200() {
        ScimGroup group = createMockGroup("Engineers");

        Map<String, Object> groupCountResult = Map.of("totalResults", 1L, "Resources", Collections.emptyList());
        Map<String, Object> groupPageResult = Map.of("totalResults", 1L, "Resources", List.of(group));

        when(groupService.listGroups(eq(wsUuid), anyString(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(groupCountResult);
        when(groupService.listGroups(eq(wsUuid), anyString(), eq("displayName"), eq("ascending"), eq(1), eq(100)))
                .thenReturn(groupPageResult);

        ResponseEntity<Map<String, Object>> response = controller.rootSearchGet(
                workspaceId, "meta.resourceType eq \"Group\"", 1, 100, "displayName", "ascending",
                null, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        Map<String, Object> body = response.getBody();
        assertNotNull(body);
        assertEquals(1L, body.get("totalResults"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> resources = (List<Map<String, Object>>) body.get("Resources");
        assertEquals(1, resources.size());
        assertEquals("Engineers", resources.get(0).get("displayName"));
    }

    @Test
    void rootSearchGetUnfilteredReturnsUsersAndGroups() {
        ScimUser user = createMockUser("bob");
        ScimGroup group = createMockGroup("Developers");

        when(userService.listUsers(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));
        when(groupService.listGroups(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));

        when(userService.listUsers(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(1)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(user)));
        when(groupService.listGroups(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(9)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(group)));
        when(userService.getUserGroupsBatch(anyList(), anyString()))
                .thenReturn(Collections.emptyMap());

        ResponseEntity<Map<String, Object>> response = controller.rootSearchGet(
                workspaceId, null, 1, 10, null, "ascending",
                null, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        Map<String, Object> body = response.getBody();
        assertNotNull(body);
        assertEquals(2L, body.get("totalResults"));
        assertEquals(2, body.get("itemsPerPage"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> resources = (List<Map<String, Object>>) body.get("Resources");
        assertEquals(2, resources.size());
        assertEquals("bob", resources.get(0).get("userName"));
        assertEquals("Developers", resources.get(1).get("displayName"));
    }

    @Test
    void rootSearchPostReturns200() {
        ScimUser user = createMockUser("carol");

        when(userService.listUsers(eq(wsUuid), eq("userName sw \"carol\""), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));
        // Group service throws unknown attribute for userName
        when(groupService.listGroups(eq(wsUuid), eq("userName sw \"carol\""), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenThrow(new ScimException(400, "invalidFilter", "Unknown attribute: userName"));

        when(userService.listUsers(eq(wsUuid), eq("userName sw \"carol\""), isNull(), eq("ascending"), eq(1), eq(10)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(user)));
        when(userService.getUserGroupsBatch(anyList(), anyString()))
                .thenReturn(Collections.emptyMap());

        Map<String, Object> searchBody = Map.of(
                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:SearchRequest"),
                "filter", "userName sw \"carol\"",
                "count", 10
        );

        ResponseEntity<Map<String, Object>> response = controller.rootSearchPost(
                workspaceId, searchBody, null, request);

        assertEquals(200, response.getStatusCode().value());
        Map<String, Object> body = response.getBody();
        assertNotNull(body);
        assertEquals(1L, body.get("totalResults"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> resources = (List<Map<String, Object>>) body.get("Resources");
        assertEquals(1, resources.size());
        assertEquals("carol", resources.get(0).get("userName"));
    }

    @Test
    void rootSearchInvalidCompatReturns404() {
        assertThrows(ScimException.class, () ->
                controller.rootSearchGet(workspaceId, null, 1, 10, null, "ascending",
                        null, null, "invalid-compat-value", request));
    }

    @Test
    void rootMethodNotAllowedReturns405() {
        ResponseEntity<Map<String, Object>> response = controller.rootMethodNotAllowed(null);
        assertEquals(405, response.getStatusCode().value());
    }
}
