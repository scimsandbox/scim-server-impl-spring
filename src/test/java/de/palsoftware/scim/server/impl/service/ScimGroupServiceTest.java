package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.model.ScimGroupMembership;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.repository.ScimGroupMembershipRepository;
import de.palsoftware.scim.server.impl.repository.ScimGroupRepository;
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
class ScimGroupServiceTest {

    @Mock
    private ScimGroupRepository groupRepository;

    @Mock
    private ScimGroupMembershipRepository membershipRepository;

    @Mock
    private ScimUserRepository userRepository;

    @Mock
    private WorkspaceRepository workspaceRepository;

    @Mock
    private WorkspaceActivityService workspaceActivityService;

    @InjectMocks
    private ScimGroupService service;

    private final UUID workspaceId = UUID.randomUUID();
    private final UUID groupId = UUID.randomUUID();
    private Workspace workspace;
    private ScimGroup group;
    private ScimUser user;

    @BeforeEach
    void setUp() {
        workspace = new Workspace();
        workspace.setId(workspaceId);

        group = new ScimGroup();
        group.setId(groupId);
        group.setWorkspace(workspace);
        group.setDisplayName("TestGroup");
        group.setVersion(1L);

        user = new ScimUser();
        user.setId(UUID.randomUUID());
        user.setWorkspace(workspace);
        user.setUserName("member1");
        user.setDisplayName("Member One");
    }

    @Test
    void createGroup_missingDisplayName_throwsError() {
        Map<String, Object> input = new HashMap<>();
        
        ScimException error = catchThrowableOfType(ScimException.class, () -> service.createGroup(workspaceId, input));
        
        assertThat(error).isNotNull();
        assertThat(error.getHttpStatus()).isEqualTo(400);
        assertThat(error.getScimType()).isEqualTo("invalidValue");
    }

    @Test
    void createGroup_duplicateName_throwsError() {
        Map<String, Object> input = Map.of("displayName", "TestGroup");
        when(groupRepository.findByDisplayNameAndWorkspaceId("TestGroup", workspaceId))
                .thenReturn(Optional.of(group));

        ScimException error = catchThrowableOfType(ScimException.class, () -> service.createGroup(workspaceId, input));
        
        assertThat(error).isNotNull();
        assertThat(error.getHttpStatus()).isEqualTo(409);
    }

    @Test
    void createGroup_success_noMembers() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(groupRepository.save(any(ScimGroup.class))).thenAnswer(i -> {
            ScimGroup g = i.getArgument(0);
            g.setId(groupId);
            return g;
        });

        Map<String, Object> input = Map.of("displayName", "NewGroup", "externalId", "ext-1");
        ScimGroup result = service.createGroup(workspaceId, input);

        assertThat(result).isNotNull();
        assertThat(result.getDisplayName()).isEqualTo("NewGroup");
        assertThat(result.getExternalId()).isEqualTo("ext-1");
        verify(groupRepository).save(any(ScimGroup.class));
        verify(workspaceActivityService).touchWorkspace(workspaceId);
    }

    @Test
    void createGroup_success_withMembers() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.findByIdAndWorkspaceId(user.getId(), workspaceId)).thenReturn(Optional.of(user));
        when(groupRepository.save(any(ScimGroup.class))).thenAnswer(i -> {
            ScimGroup g = i.getArgument(0);
            if (g.getId() == null) g.setId(groupId);
            return g;
        });

        List<Map<String, Object>> members = List.of(Map.of("value", user.getId().toString(), "type", "User"));
        Map<String, Object> input = new HashMap<>();
        input.put("displayName", "NewGroup");
        input.put("members", members);

        ScimGroup result = service.createGroup(workspaceId, input);

        assertThat(result.getMembers()).hasSize(1);
        ScimGroupMembership member = result.getMembers().get(0);
        assertThat(member.getMemberValue()).isEqualTo(user.getId());
        assertThat(member.getDisplay()).isEqualTo("Member One");
    }

    @Test
    void getGroup_notFound_throwsError() {
        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.empty());
        
        ScimException error = catchThrowableOfType(ScimException.class, () -> service.getGroup(workspaceId, groupId));
        
        assertThat(error).isNotNull();
        assertThat(error.getHttpStatus()).isEqualTo(404);
    }

    @Test
    void listGroups_success() {
        when(groupRepository.count(org.mockito.ArgumentMatchers.<Specification<ScimGroup>>any())).thenReturn(10L);
        when(groupRepository.findAll(org.mockito.ArgumentMatchers.<Specification<ScimGroup>>any(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(group)));

        Map<String, Object> response = service.listGroups(workspaceId, null, "displayName", "ascending", 1, 10);

        assertThat(response).containsEntry("totalResults", 10L);
        List<?> resources = (List<?>) response.get("Resources");
        assertThat(resources).hasSize(1);
    }

    @Test
    void replaceGroup_eTagMismatch_throwsError() {
        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));
        Map<String, Object> input = Map.of("displayName", "newname");
        
        ScimException error = catchThrowableOfType(ScimException.class, () -> service.replaceGroup(workspaceId, groupId, input, "W/\"999\""));
        
        assertThat(error.getHttpStatus()).isEqualTo(412);
    }

    @Test
    void replaceGroup_duplicateName_throwsError() {
        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));
        when(groupRepository.findByDisplayNameAndWorkspaceId("newname", workspaceId)).thenReturn(Optional.of(new ScimGroup()));
        
        Map<String, Object> input = Map.of("displayName", "newname");
        
        ScimException error = catchThrowableOfType(ScimException.class, () -> service.replaceGroup(workspaceId, groupId, input, null));
        
        assertThat(error.getHttpStatus()).isEqualTo(409);
    }

    @Test
    void patchGroup_addMember_success() {
        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));
        when(userRepository.findByIdAndWorkspaceId(user.getId(), workspaceId)).thenReturn(Optional.of(user));
        when(groupRepository.save(any(ScimGroup.class))).thenReturn(group);

        List<Map<String, Object>> ops = List.of(
            Map.of("op", "add", "path", "members", "value", List.of(
                Map.of("value", user.getId().toString())
            ))
        );

        ScimGroup result = service.patchGroup(workspaceId, groupId, ops, null);

        assertThat(result.getMembers()).hasSize(1);
        verify(groupRepository).save(group);
    }
    
    @Test
    void patchGroup_replaceDisplayName_success() {
        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));
        when(groupRepository.save(any(ScimGroup.class))).thenReturn(group);

        List<Map<String, Object>> ops = List.of(
            Map.of("op", "replace", "path", "displayName", "value", "UpdatedName")
        );

        ScimGroup result = service.patchGroup(workspaceId, groupId, ops, null);

        assertThat(result.getDisplayName()).isEqualTo("UpdatedName");
    }

    @Test
    void deleteGroup_success() {
        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));

        service.deleteGroup(workspaceId, groupId);

        verify(membershipRepository).deleteByMemberValue(groupId);
        verify(groupRepository).delete(group);
        verify(workspaceActivityService).touchWorkspace(workspaceId);
    }
}
