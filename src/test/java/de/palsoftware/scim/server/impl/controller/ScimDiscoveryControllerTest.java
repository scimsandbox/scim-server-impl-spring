package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.model.ScimUserEmail;
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

    @Test
    void rootSearchCombinedSortingOrdersAcrossTypesAscending() {
        ScimUser userBob = createMockUser("bob");
        userBob.setDisplayName("Bob");
        ScimGroup groupAlice = createMockGroup("Alice");

        when(userService.listUsers(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));
        when(groupService.listGroups(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));

        when(userService.listUsers(eq(wsUuid), isNull(), eq("displayName"), eq("ascending"), eq(1), anyInt()))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(userBob)));
        when(groupService.listGroups(eq(wsUuid), isNull(), eq("displayName"), eq("ascending"), eq(1), anyInt()))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(groupAlice)));
        when(userService.getUserGroupsBatch(anyList(), anyString()))
                .thenReturn(Collections.emptyMap());

        ResponseEntity<Map<String, Object>> response = controller.rootSearchGet(
                workspaceId, null, 1, 10, "displayName", "ascending",
                null, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        Map<String, Object> body = response.getBody();
        assertNotNull(body);
        assertEquals(2L, body.get("totalResults"));
        assertEquals(2, body.get("itemsPerPage"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> resources = (List<Map<String, Object>>) body.get("Resources");
        assertEquals(2, resources.size());
        assertEquals("Alice", resources.get(0).get("displayName"));
        assertEquals("Group", ((Map<?, ?>) resources.get(0).get("meta")).get("resourceType"));
        assertEquals("Bob", resources.get(1).get("displayName"));
        assertEquals("User", ((Map<?, ?>) resources.get(1).get("meta")).get("resourceType"));
    }

    @Test
    void rootSearchCombinedSortingOrdersAcrossTypesDescending() {
        ScimUser userBob = createMockUser("bob");
        userBob.setDisplayName("Bob");
        ScimGroup groupAlice = createMockGroup("Alice");

        when(userService.listUsers(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));
        when(groupService.listGroups(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));

        when(userService.listUsers(eq(wsUuid), isNull(), eq("displayName"), eq("descending"), eq(1), anyInt()))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(userBob)));
        when(groupService.listGroups(eq(wsUuid), isNull(), eq("displayName"), eq("descending"), eq(1), anyInt()))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(groupAlice)));
        when(userService.getUserGroupsBatch(anyList(), anyString()))
                .thenReturn(Collections.emptyMap());

        ResponseEntity<Map<String, Object>> response = controller.rootSearchGet(
                workspaceId, null, 1, 10, "displayName", "descending",
                null, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        Map<String, Object> body = response.getBody();
        assertNotNull(body);
        assertEquals(2L, body.get("totalResults"));
        assertEquals(2, body.get("itemsPerPage"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> resources = (List<Map<String, Object>>) body.get("Resources");
        assertEquals(2, resources.size());
        assertEquals("Bob", resources.get(0).get("displayName"));
        assertEquals("User", ((Map<?, ?>) resources.get(0).get("meta")).get("resourceType"));
        assertEquals("Alice", resources.get(1).get("displayName"));
        assertEquals("Group", ((Map<?, ?>) resources.get(1).get("meta")).get("resourceType"));
    }

    @Test
    void rootSearchCombinedSortingWithAttributeProjection() {
        ScimUser userBob = createMockUser("bob");
        userBob.setDisplayName("Bob");
        ScimGroup groupAlice = createMockGroup("Alice");

        when(userService.listUsers(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));
        when(groupService.listGroups(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));

        when(userService.listUsers(eq(wsUuid), isNull(), eq("displayName"), eq("ascending"), eq(1), anyInt()))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(userBob)));
        when(groupService.listGroups(eq(wsUuid), isNull(), eq("displayName"), eq("ascending"), eq(1), anyInt()))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(groupAlice)));
        when(userService.getUserGroupsBatch(anyList(), anyString()))
                .thenReturn(Collections.emptyMap());

        ResponseEntity<Map<String, Object>> response = controller.rootSearchGet(
                workspaceId, null, 1, 10, "displayName", "ascending",
                "id,meta.resourceType", null, null, request);

        assertEquals(200, response.getStatusCode().value());
        Map<String, Object> body = response.getBody();
        assertNotNull(body);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> resources = (List<Map<String, Object>>) body.get("Resources");
        assertEquals(2, resources.size());
        assertEquals("Group", ((Map<?, ?>) resources.get(0).get("meta")).get("resourceType"));
        assertEquals("User", ((Map<?, ?>) resources.get(1).get("meta")).get("resourceType"));
        assertFalse(resources.get(0).containsKey("displayName"));
        assertFalse(resources.get(1).containsKey("displayName"));
    }

    @Test
    void rootSearchCombinedSortingNullsLastOnAscending() {
        ScimUser userNullDisplay = createMockUser("user1");
        userNullDisplay.setDisplayName(null);
        ScimGroup groupAlice = createMockGroup("Alice");

        when(userService.listUsers(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));
        when(groupService.listGroups(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));

        when(userService.listUsers(eq(wsUuid), isNull(), eq("displayName"), eq("ascending"), eq(1), anyInt()))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(userNullDisplay)));
        when(groupService.listGroups(eq(wsUuid), isNull(), eq("displayName"), eq("ascending"), eq(1), anyInt()))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(groupAlice)));
        when(userService.getUserGroupsBatch(anyList(), anyString()))
                .thenReturn(Collections.emptyMap());

        ResponseEntity<Map<String, Object>> response = controller.rootSearchGet(
                workspaceId, null, 1, 10, "displayName", "ascending",
                null, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> resources = (List<Map<String, Object>>) response.getBody().get("Resources");
        assertEquals(2, resources.size());
        assertEquals("Alice", resources.get(0).get("displayName"));
        assertEquals("Group", ((Map<?, ?>) resources.get(0).get("meta")).get("resourceType"));
        assertNull(resources.get(1).get("displayName"));
        assertEquals("User", ((Map<?, ?>) resources.get(1).get("meta")).get("resourceType"));
    }

    @Test
    void rootSearchCombinedSortingNullsFirstOnDescending() {
        ScimUser userNullDisplay = createMockUser("user1");
        userNullDisplay.setDisplayName(null);
        ScimGroup groupAlice = createMockGroup("Alice");

        when(userService.listUsers(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));
        when(groupService.listGroups(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));

        when(userService.listUsers(eq(wsUuid), isNull(), eq("displayName"), eq("descending"), eq(1), anyInt()))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(userNullDisplay)));
        when(groupService.listGroups(eq(wsUuid), isNull(), eq("displayName"), eq("descending"), eq(1), anyInt()))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(groupAlice)));
        when(userService.getUserGroupsBatch(anyList(), anyString()))
                .thenReturn(Collections.emptyMap());

        ResponseEntity<Map<String, Object>> response = controller.rootSearchGet(
                workspaceId, null, 1, 10, "displayName", "descending",
                null, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> resources = (List<Map<String, Object>>) response.getBody().get("Resources");
        assertEquals(2, resources.size());
        assertNull(resources.get(0).get("displayName"));
        assertEquals("User", ((Map<?, ?>) resources.get(0).get("meta")).get("resourceType"));
        assertEquals("Alice", resources.get(1).get("displayName"));
        assertEquals("Group", ((Map<?, ?>) resources.get(1).get("meta")).get("resourceType"));
    }

    @Test
    void rootSearchPostCombinedSortingOrdersAcrossTypes() {
        ScimUser userBob = createMockUser("bob");
        userBob.setDisplayName("Bob");
        ScimGroup groupAlice = createMockGroup("Alice");

        when(userService.listUsers(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));
        when(groupService.listGroups(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));

        when(userService.listUsers(eq(wsUuid), isNull(), eq("displayName"), eq("ascending"), eq(1), anyInt()))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(userBob)));
        when(groupService.listGroups(eq(wsUuid), isNull(), eq("displayName"), eq("ascending"), eq(1), anyInt()))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(groupAlice)));
        when(userService.getUserGroupsBatch(anyList(), anyString()))
                .thenReturn(Collections.emptyMap());

        Map<String, Object> searchBody = Map.of(
                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:SearchRequest"),
                "sortBy", "displayName",
                "sortOrder", "ascending",
                "count", 10
        );

        ResponseEntity<Map<String, Object>> response = controller.rootSearchPost(
                workspaceId, searchBody, null, request);

        assertEquals(200, response.getStatusCode().value());
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> resources = (List<Map<String, Object>>) response.getBody().get("Resources");
        assertEquals(2, resources.size());
        assertEquals("Alice", resources.get(0).get("displayName"));
        assertEquals("Bob", resources.get(1).get("displayName"));
    }

    @Test
    void rootSearchCombinedSortingPaginationSlice() {
        ScimUser userBob = createMockUser("bob");
        userBob.setDisplayName("Bob");
        ScimGroup groupAlice = createMockGroup("Alice");
        ScimGroup groupCharlie = createMockGroup("Charlie");

        when(userService.listUsers(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));
        when(groupService.listGroups(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 2L, "Resources", Collections.emptyList()));

        when(userService.listUsers(eq(wsUuid), isNull(), eq("displayName"), eq("ascending"), eq(1), anyInt()))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(userBob)));
        when(groupService.listGroups(eq(wsUuid), isNull(), eq("displayName"), eq("ascending"), eq(1), anyInt()))
                .thenReturn(Map.of("totalResults", 2L, "Resources", List.of(groupAlice, groupCharlie)));
        when(userService.getUserGroupsBatch(anyList(), anyString()))
                .thenReturn(Collections.emptyMap());

        ResponseEntity<Map<String, Object>> response = controller.rootSearchGet(
                workspaceId, null, 2, 1, "displayName", "ascending",
                null, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        Map<String, Object> body = response.getBody();
        assertNotNull(body);
        assertEquals(3L, body.get("totalResults"));
        assertEquals(2, body.get("startIndex"));
        assertEquals(1, body.get("itemsPerPage"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> resources = (List<Map<String, Object>>) body.get("Resources");
        assertEquals(1, resources.size());
        assertEquals("Bob", resources.get(0).get("displayName"));
        assertEquals("User", ((Map<?, ?>) resources.get(0).get("meta")).get("resourceType"));
    }

    @Test
    void rootSearchCombinedSortingEnterpriseDepartmentAscending() {
        ScimUser user = createMockUser("dave");
        user.setDisplayName("Dave");
        user.setEnterpriseDepartment("Engineering");
        ScimGroup group = createMockGroup("Admins");

        when(userService.listUsers(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));
        when(groupService.listGroups(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));

        when(userService.listUsers(eq(wsUuid), isNull(), eq("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"), eq("ascending"), eq(1), anyInt()))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(user)));
        when(groupService.listGroups(eq(wsUuid), isNull(), eq("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"), eq("ascending"), eq(1), anyInt()))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(group)));
        when(userService.getUserGroupsBatch(anyList(), anyString()))
                .thenReturn(Collections.emptyMap());

        ResponseEntity<Map<String, Object>> response = controller.rootSearchGet(
                workspaceId, null, 1, 10,
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", "ascending",
                null, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> resources = (List<Map<String, Object>>) response.getBody().get("Resources");
        assertEquals(2, resources.size());
        // User has non-null department "Engineering", Group has null enterprise department -> User first, Group last
        assertEquals("User", ((Map<?, ?>) resources.get(0).get("meta")).get("resourceType"));
        assertEquals("Group", ((Map<?, ?>) resources.get(1).get("meta")).get("resourceType"));
    }

    @Test
    void rootSearchCombinedSortingEmailPrimaryAscending() {
        ScimUser user = createMockUser("eve");
        user.setDisplayName("Eve");
        ScimUserEmail email = new ScimUserEmail();
        email.setValue("eve@example.com");
        email.setPrimaryFlag(true);
        user.setEmails(List.of(email));
        ScimGroup group = createMockGroup("Auditors");

        when(userService.listUsers(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));
        when(groupService.listGroups(eq(wsUuid), isNull(), isNull(), eq("ascending"), eq(1), eq(0)))
                .thenReturn(Map.of("totalResults", 1L, "Resources", Collections.emptyList()));

        when(userService.listUsers(eq(wsUuid), isNull(), eq("emails"), eq("ascending"), eq(1), anyInt()))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(user)));
        when(groupService.listGroups(eq(wsUuid), isNull(), eq("emails"), eq("ascending"), eq(1), anyInt()))
                .thenReturn(Map.of("totalResults", 1L, "Resources", List.of(group)));
        when(userService.getUserGroupsBatch(anyList(), anyString()))
                .thenReturn(Collections.emptyMap());

        ResponseEntity<Map<String, Object>> response = controller.rootSearchGet(
                workspaceId, null, 1, 10, "emails", "ascending",
                null, null, null, request);

        assertEquals(200, response.getStatusCode().value());
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> resources = (List<Map<String, Object>>) response.getBody().get("Resources");
        assertEquals(2, resources.size());
        assertEquals("User", ((Map<?, ?>) resources.get(0).get("meta")).get("resourceType"));
        assertEquals("Group", ((Map<?, ?>) resources.get(1).get("meta")).get("resourceType"));
    }
}
