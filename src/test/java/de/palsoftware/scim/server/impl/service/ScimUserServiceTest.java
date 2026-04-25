package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.model.ScimGroupMembership;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.repository.ScimGroupMembershipRepository;
import de.palsoftware.scim.server.impl.repository.ScimUserRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;


import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScimUserServiceTest {

    @Mock
    private ScimUserRepository userRepository;

    @Mock
    private ScimGroupMembershipRepository membershipRepository;

    @Mock
    private WorkspaceRepository workspaceRepository;

    @Mock
    private WorkspaceActivityService workspaceActivityService;

    @InjectMocks
    private ScimUserService service;

    private final UUID workspaceId = UUID.randomUUID();
    private final UUID userId = UUID.randomUUID();
    private Workspace workspace;
    private ScimUser user;

    @BeforeEach
    void setUp() {
        workspace = new Workspace();
        workspace.setId(workspaceId);

        user = new ScimUser();
        user.setId(userId);
        user.setWorkspace(workspace);
        user.setUserName("testuser");
        user.setVersion(1L);
    }

    @Test
    void createUser_missingUserName_throwsError() {
        Map<String, Object> input = new HashMap<>();
        
        ScimException error = catchThrowableOfType(ScimException.class, () -> service.createUser(workspaceId, input));
        
        assertThat(error).isNotNull();
        assertThat(error.getHttpStatus()).isEqualTo(400);
        assertThat(error.getScimType()).isEqualTo("invalidValue");
    }

    @Test
    void createUser_duplicateUserName_throwsError() {
        Map<String, Object> input = Map.of("userName", "testuser");
        when(userRepository.existsByUserNameIgnoreCaseAndWorkspaceId("testuser", workspaceId)).thenReturn(true);
        
        ScimException error = catchThrowableOfType(ScimException.class, () -> service.createUser(workspaceId, input));
        
        assertThat(error).isNotNull();
        assertThat(error.getHttpStatus()).isEqualTo(409);
        assertThat(error.getScimType()).isEqualTo("uniqueness");
    }

    @Test
    void createUser_workspaceNotFound_throwsError() {
        Map<String, Object> input = Map.of("userName", "testuser");
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.empty());
        
        ScimException error = catchThrowableOfType(ScimException.class, () -> service.createUser(workspaceId, input));
        
        assertThat(error).isNotNull();
        assertThat(error.getHttpStatus()).isEqualTo(404);
    }

    @Test
    void createUser_success() {
        Map<String, Object> input = Map.of("userName", "testuser", "displayName", "Test User");
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.save(any(ScimUser.class))).thenAnswer(i -> {
            ScimUser u = i.getArgument(0);
            u.setId(userId);
            return u;
        });

        ScimUser result = service.createUser(workspaceId, input);

        assertThat(result).isNotNull();
        assertThat(result.getUserName()).isEqualTo("testuser");
        assertThat(result.getDisplayName()).isEqualTo("Test User");
        verify(userRepository).save(any(ScimUser.class));
        verify(workspaceActivityService).touchWorkspace(workspaceId);
    }

    @Test
    void getUser_notFound_throwsError() {
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.empty());
        
        ScimException error = catchThrowableOfType(ScimException.class, () -> service.getUser(workspaceId, userId));
        
        assertThat(error).isNotNull();
        assertThat(error.getHttpStatus()).isEqualTo(404);
    }

    @Test
    void getUser_success() {
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.of(user));
        
        ScimUser result = service.getUser(workspaceId, userId);
        
        assertThat(result).isEqualTo(user);
    }

    @Test
    void listUsers_zeroCount_returnsEmptyCorrectly() {
        when(userRepository.count(org.mockito.ArgumentMatchers.<Specification<ScimUser>>any())).thenReturn(5L);

        Map<String, Object> response = service.listUsers(workspaceId, null, null, null, 1, 0);

        assertThat(response)
            .containsEntry("totalResults", 5L)
            .containsEntry("itemsPerPage", 0);
        assertThat((List<?>) response.get("Resources")).isEmpty();
    }

    @Test
    @SuppressWarnings("unchecked")
    void listUsers_success() {
        when(userRepository.count(org.mockito.ArgumentMatchers.<Specification<ScimUser>>any())).thenReturn(10L);
        when(userRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(user)));

        Map<String, Object> response = service.listUsers(workspaceId, null, "userName", "ascending", 1, 10);

        assertThat(response)
            .containsEntry("totalResults", 10L)
            .containsEntry("startIndex", 1)
            .containsEntry("itemsPerPage", 1);
        List<ScimUser> resources = (List<ScimUser>) response.get("Resources");
        assertThat(resources).hasSize(1);
        assertThat(resources.get(0).getId()).isEqualTo(userId);
    }

    @Test
    void replaceUser_eTagMismatch_throwsError() {
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.of(user));
        Map<String, Object> input = Map.of("userName", "newname");
        
        ScimException error = catchThrowableOfType(ScimException.class, () -> service.replaceUser(workspaceId, userId, input, "W/\"999\""));
        
        assertThat(error).isNotNull();
        assertThat(error.getHttpStatus()).isEqualTo(412);
    }

    @Test
    void replaceUser_conflictUserName_throwsError() {
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.of(user));
        when(userRepository.existsByUserNameIgnoreCaseAndWorkspaceId("newname", workspaceId)).thenReturn(true);
        Map<String, Object> input = Map.of("userName", "newname");
        
        ScimException error = catchThrowableOfType(ScimException.class, () -> service.replaceUser(workspaceId, userId, input, null));
        
        assertThat(error).isNotNull();
        assertThat(error.getHttpStatus()).isEqualTo(409);
    }

    @Test
    void replaceUser_success() {
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.of(user));
        when(userRepository.save(any(ScimUser.class))).thenReturn(user);
        Map<String, Object> input = Map.of("userName", "testuser", "displayName", "Replaced");

        ScimUser result = service.replaceUser(workspaceId, userId, input, "W/\"1\"");

        assertThat(result).isNotNull();
        verify(userRepository).save(user);
        assertThat(user.getDisplayName()).isEqualTo("Replaced");
        verify(workspaceActivityService).touchWorkspace(workspaceId);
    }

    @Test
    void patchUser_eTagMismatch_throwsError() {
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.of(user));
        
        ScimException error = catchThrowableOfType(ScimException.class, () -> service.patchUser(workspaceId, userId, Collections.emptyList(), "W/\"999\""));
        
        assertThat(error).isNotNull();
        assertThat(error.getHttpStatus()).isEqualTo(412);
    }

    @Test
    void patchUser_success() {
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.of(user));
        when(userRepository.save(any(ScimUser.class))).thenReturn(user);
        
        List<Map<String, Object>> ops = List.of(Map.of("op", "replace", "path", "displayName", "value", "Patched User"));

        ScimUser result = service.patchUser(workspaceId, userId, ops, null);

        assertThat(result).isNotNull();
        verify(userRepository).save(user);
        assertThat(user.getDisplayName()).isEqualTo("Patched User");
        verify(workspaceActivityService).touchWorkspace(workspaceId);
    }

    @Test
    void deleteUser_success() {
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.of(user));

        service.deleteUser(workspaceId, userId);

        verify(membershipRepository).deleteByMemberValue(userId);
        verify(userRepository).delete(user);
        verify(workspaceActivityService).touchWorkspace(workspaceId);
    }

    @Test
    void getUserGroups_returnsCorrectMapping() {
        ScimGroup group = new ScimGroup();
        UUID groupId = UUID.randomUUID();
        group.setId(groupId);
        group.setDisplayName("Test Group");
        
        ScimGroupMembership membership = new ScimGroupMembership();
        membership.setGroup(group);
        membership.setMemberValue(userId);
        membership.setMemberType("User");

        when(membershipRepository.findByMemberValue(userId)).thenReturn(List.of(membership));

        List<Map<String, Object>> groups = service.getUserGroups(userId, "http://localhost");

        assertThat(groups).hasSize(1);
        assertThat(groups.get(0))
            .containsEntry("value", groupId.toString())
            .containsEntry("display", "Test Group")
            .containsEntry("$ref", "http://localhost/Groups/" + groupId)
            .containsEntry("type", "direct");
    }

    @Test
    void getUserGroupsBatch_returnsCorrectMapping() {
        ScimGroup group = new ScimGroup();
        UUID groupId = UUID.randomUUID();
        group.setId(groupId);
        group.setDisplayName("Batch Group");
        
        ScimGroupMembership membership = new ScimGroupMembership();
        membership.setGroup(group);
        membership.setMemberValue(userId);
        membership.setMemberType("User");

        when(membershipRepository.findByMemberValueIn(List.of(userId))).thenReturn(List.of(membership));

        Map<UUID, List<Map<String, Object>>> batchMap = service.getUserGroupsBatch(List.of(userId), "http://loc");

        assertThat(batchMap).containsKey(userId);
        List<Map<String, Object>> userList = batchMap.get(userId);
        assertThat(userList).hasSize(1);
        assertThat(userList.get(0))
            .containsEntry("value", groupId.toString())
            .containsEntry("display", "Batch Group")
            .containsEntry("$ref", "http://loc/Groups/" + groupId);
    }
}
