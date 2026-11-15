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
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
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

        verify(membershipRepository).deleteByMemberValueAndWorkspaceId(groupId, workspaceId);
        verify(groupRepository).delete(group);
        verify(workspaceActivityService).touchWorkspace(workspaceId);
    }

    @Test
    @SuppressWarnings("unchecked")
    void listGroups_ascending_usesNullsLast() {
        when(groupRepository.count(org.mockito.ArgumentMatchers.<Specification<ScimGroup>>any())).thenReturn(1L);
        when(groupRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(group)));

        Map<String, Object> response = service.listGroups(workspaceId, null, "externalId", "ascending", 1, 10);

        assertThat(response).containsEntry("totalResults", 1L).containsEntry("itemsPerPage", 1);
        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(groupRepository).findAll(any(Specification.class), pageableCaptor.capture());
        Sort sort = pageableCaptor.getValue().getSort();
        Sort.Order order = sort.getOrderFor("externalId");
        assertThat(order).isNotNull();
        assertThat(order.isAscending()).isTrue();
        assertThat(order.isIgnoreCase()).isFalse();
        assertThat(order.getNullHandling()).isEqualTo(Sort.NullHandling.NULLS_LAST);
    }

    @Test
    @SuppressWarnings("unchecked")
    void listGroups_displayName_ignoresCase() {
        when(groupRepository.count(org.mockito.ArgumentMatchers.<Specification<ScimGroup>>any())).thenReturn(1L);
        when(groupRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(group)));

        service.listGroups(workspaceId, null, "displayName", "ascending", 1, 10);

        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(groupRepository).findAll(any(Specification.class), pageableCaptor.capture());
        Sort.Order order = pageableCaptor.getValue().getSort().getOrderFor("displayName");
        assertThat(order).isNotNull();
        assertThat(order.isIgnoreCase()).isTrue();
        assertThat(order.getNullHandling()).isEqualTo(Sort.NullHandling.NULLS_LAST);
    }

    @Test
    @SuppressWarnings("unchecked")
    void listGroups_descending_usesNullsFirst() {
        when(groupRepository.count(org.mockito.ArgumentMatchers.<Specification<ScimGroup>>any())).thenReturn(1L);
        when(groupRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(group)));

        Map<String, Object> response = service.listGroups(workspaceId, null, "externalId", "descending", 1, 10);

        assertThat(response).containsEntry("totalResults", 1L).containsEntry("itemsPerPage", 1);
        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(groupRepository).findAll(any(Specification.class), pageableCaptor.capture());
        Sort sort = pageableCaptor.getValue().getSort();
        Sort.Order order = sort.getOrderFor("externalId");
        assertThat(order).isNotNull();
        assertThat(order.isDescending()).isTrue();
        assertThat(order.getNullHandling()).isEqualTo(Sort.NullHandling.NULLS_FIRST);
    }

    @Test
    void replaceGroup_wildcardIfMatch_success() {
        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));
        when(groupRepository.save(any(ScimGroup.class))).thenReturn(group);
        Map<String, Object> input = Map.of("displayName", "WildcardGroup");

        ScimGroup result = service.replaceGroup(workspaceId, groupId, input, "*");

        assertThat(result).isNotNull();
        assertThat(group.getDisplayName()).isEqualTo("WildcardGroup");
    }

    @Test
    void patchGroup_wildcardIfMatch_success() {
        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));
        when(groupRepository.save(any(ScimGroup.class))).thenReturn(group);

        List<Map<String, Object>> ops = List.of(
            Map.of("op", "replace", "path", "displayName", "value", "WildcardPatched")
        );

        ScimGroup result = service.patchGroup(workspaceId, groupId, ops, "*");

        assertThat(result).isNotNull();
        assertThat(group.getDisplayName()).isEqualTo("WildcardPatched");
    }

    @Test
    void replaceGroup_alterMemberType_throwsMutabilityError() {
        // Setup group with existing User member
        ScimGroupMembership membership = new ScimGroupMembership();
        membership.setGroup(group);
        membership.setMemberValue(user.getId());
        membership.setMemberType("User");
        group.getMembers().add(membership);

        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));

        Map<String, Object> input = Map.of(
            "displayName", group.getDisplayName(),
            "members", List.of(
                Map.of("value", user.getId().toString(), "type", "Group")
            )
        );

        ScimException error = catchThrowableOfType(ScimException.class,
                () -> service.replaceGroup(workspaceId, groupId, input, null));

        assertThat(error).isNotNull();
        assertThat(error.getHttpStatus()).isEqualTo(400);
        assertThat(error.getScimType()).isEqualTo("mutability");
    }

    @Test
    void patchGroup_addWithoutValue_throws400() {
        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));

        List<Map<String, Object>> ops = List.of(
            Map.of("op", "add", "path", "displayName")
        );

        ScimException error = catchThrowableOfType(ScimException.class,
                () -> service.patchGroup(workspaceId, groupId, ops, null));

        assertThat(error).isNotNull();
        assertThat(error.getHttpStatus()).isEqualTo(400);
        assertThat(error.getScimType()).isEqualTo("invalidValue");
    }

    @Test
    void patchGroup_replaceDisplayName_excludesSelfFromUniquenessCheck() {
        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));
        // Simulate auto-flush returning the group itself on findByDisplayNameAndWorkspaceId
        when(groupRepository.findByDisplayNameAndWorkspaceId("RenamedGroup", workspaceId))
                .thenReturn(Optional.of(group));
        when(groupRepository.save(any(ScimGroup.class))).thenReturn(group);

        List<Map<String, Object>> ops = List.of(
                Map.of("op", "replace", "path", "displayName", "value", "RenamedGroup")
        );

        ScimGroup result = service.patchGroup(workspaceId, groupId, ops, null);
        assertThat(result.getDisplayName()).isEqualTo("RenamedGroup");
    }

    @Test
    void patchGroup_removeDisplayName_throwsMutability() {
        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));

        List<Map<String, Object>> ops = List.of(Map.of("op", "remove", "path", "displayName"));
        ScimException error = catchThrowableOfType(ScimException.class,
                () -> service.patchGroup(workspaceId, groupId, ops, null));

        assertThat(error).isNotNull();
        assertThat(error.getHttpStatus()).isEqualTo(400);
        assertThat(error.getScimType()).isEqualTo("mutability");
    }

    @Test
    void patchGroup_noopDoesNotSave() {
        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));

        List<Map<String, Object>> ops = List.of(
                Map.of("op", "replace", "path", "displayName", "value", "TestGroup")
        );

        ScimGroup result = service.patchGroup(workspaceId, groupId, ops, null);
        assertThat(result).isSameAs(group);
        org.mockito.Mockito.verify(groupRepository, org.mockito.Mockito.never()).save(any());
    }

    @Test
    void createGroup_supportsNestedGroupMemberWhenTypeOmitted() {
        UUID childGroupId = UUID.randomUUID();
        ScimGroup childGroup = new ScimGroup();
        childGroup.setId(childGroupId);
        childGroup.setWorkspace(workspace);
        childGroup.setDisplayName("Child Group");

        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.findByIdAndWorkspaceId(childGroupId, workspaceId)).thenReturn(Optional.empty());
        when(groupRepository.findByIdAndWorkspaceId(childGroupId, workspaceId)).thenReturn(Optional.of(childGroup));
        when(groupRepository.save(any(ScimGroup.class))).thenAnswer(i -> {
            ScimGroup g = i.getArgument(0);
            if (g.getId() == null) g.setId(groupId);
            return g;
        });

        Map<String, Object> input = Map.of(
                "displayName", "Parent Group",
                "members", List.of(Map.of("value", childGroupId.toString()))
        );

        ScimGroup created = service.createGroup(workspaceId, input);
        assertThat(created.getMembers()).hasSize(1);
        assertThat(created.getMembers().get(0).getMemberType()).isEqualTo("Group");
        assertThat(created.getMembers().get(0).getDisplay()).isEqualTo("Child Group");
    }

    @Test
    // RFC7643-7-031493, RFC7644-3.5.1-2e5206, RFC7643-2.4-63934b
    void replaceGroup_matchingExistingMemberTypeAndVersionAgnosticRef_succeeds() {
        ScimGroupMembership membership = new ScimGroupMembership();
        membership.setGroup(group);
        membership.setMemberValue(user.getId());
        membership.setMemberType("User");
        group.getMembers().add(membership);

        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));
        when(userRepository.findByIdAndWorkspaceId(user.getId(), workspaceId)).thenReturn(Optional.of(user));
        when(groupRepository.save(any(ScimGroup.class))).thenAnswer(i -> i.getArgument(0));

        Map<String, Object> input = Map.of(
                "displayName", group.getDisplayName(),
                "members", List.of(Map.of(
                        "value", user.getId().toString(),
                        "type", "User",
                        "$ref", "https://idp.example.com/scim/v1/Users/" + user.getId()
                ))
        );

        ScimGroup updated = service.replaceGroup(workspaceId, groupId, input, null);
        assertThat(updated.getMembers()).hasSize(1);
        assertThat(updated.getMembers().get(0).getMemberType()).isEqualTo("User");
        assertThat(updated.getMembers().get(0).getMemberValue()).isEqualTo(user.getId());
    }

    @Test
    // RFC7643-7-031493, RFC7644-3.5.1-2e5206, RFC7644-3.5.1-019f75
    void replaceGroup_alterExistingMemberRef_throwsMutabilityError() {
        ScimGroupMembership membership = new ScimGroupMembership();
        membership.setGroup(group);
        membership.setMemberValue(user.getId());
        membership.setMemberType("User");
        group.getMembers().add(membership);

        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));

        Map<String, Object> input = Map.of(
                "displayName", group.getDisplayName(),
                "members", List.of(Map.of(
                        "value", user.getId().toString(),
                        "$ref", "https://idp.example.com/scim/v2/Groups/" + user.getId()
                ))
        );

        ScimException error = catchThrowableOfType(ScimException.class,
                () -> service.replaceGroup(workspaceId, groupId, input, null));

        assertThat(error).isNotNull();
        assertThat(error.getHttpStatus()).isEqualTo(400);
        assertThat(error.getScimType()).isEqualTo("mutability");
    }

    @Test
    // RFC7643-2.4-63934b
    void replaceGroup_conflictingMemberValueAndRef_throwsInvalidValue() {
        ScimGroupMembership membership = new ScimGroupMembership();
        membership.setGroup(group);
        membership.setMemberValue(user.getId());
        membership.setMemberType("User");
        group.getMembers().add(membership);

        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));

        Map<String, Object> input = Map.of(
                "displayName", group.getDisplayName(),
                "members", List.of(Map.of(
                        "value", user.getId().toString(),
                        "type", "User",
                        "$ref", "https://idp.example.com/scim/v2/Users/" + UUID.randomUUID()
                ))
        );

        ScimException error = catchThrowableOfType(ScimException.class,
                () -> service.replaceGroup(workspaceId, groupId, input, null));

        assertThat(error).isNotNull();
        assertThat(error.getHttpStatus()).isEqualTo(400);
        assertThat(error.getScimType()).isEqualTo("invalidValue");
    }

    @Test
    // RFC7643-7-031493
    void patchGroup_replaceOrRemoveImmutableMemberSubAttributes_throwsMutabilityError() {
        ScimGroupMembership membership = new ScimGroupMembership();
        membership.setGroup(group);
        membership.setMemberValue(user.getId());
        membership.setMemberType("User");
        group.getMembers().add(membership);

        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));

        for (String op : List.of("replace", "remove")) {
            for (String subAttr : List.of("type", "value", "$ref")) {
                Map<String, Object> patchOp = new HashMap<>();
                patchOp.put("op", op);
                patchOp.put("path", "members[value eq \"" + user.getId() + "\"]." + subAttr);
                if ("replace".equals(op)) {
                    patchOp.put("value", "Group");
                }

                ScimException error = catchThrowableOfType(ScimException.class,
                        () -> service.patchGroup(workspaceId, groupId, List.of(patchOp), null));

                assertThat(error).isNotNull();
                assertThat(error.getHttpStatus()).isEqualTo(400);
                assertThat(error.getScimType()).isEqualTo("mutability");
            }
        }
    }

    @Test
    // RFC7644-3.5.2-0cc87d, RFC7643-7-031493
    void patchGroup_addMemberTypeWhenUnset_succeedsAndRejectsSubsequentConflict() {
        ScimGroupMembership membership = new ScimGroupMembership();
        membership.setGroup(group);
        membership.setMemberValue(user.getId());
        membership.setMemberType(""); // Previously unset
        group.getMembers().add(membership);

        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));
        when(userRepository.findByIdAndWorkspaceId(user.getId(), workspaceId)).thenReturn(Optional.of(user));
        when(groupRepository.save(any(ScimGroup.class))).thenAnswer(i -> i.getArgument(0));

        // Object-level PATCH replace cannot initialize a previously unset immutable 'type'
        List<Map<String, Object>> replaceUnsetTypeOps = List.of(Map.of(
                "op", "replace",
                "path", "members[value eq \"" + user.getId() + "\"]",
                "value", Map.of("type", "User")
        ));
        ScimException replaceErr = catchThrowableOfType(ScimException.class,
                () -> service.patchGroup(workspaceId, groupId, replaceUnsetTypeOps, null));
        assertThat(replaceErr).isNotNull();
        assertThat(replaceErr.getHttpStatus()).isEqualTo(400);
        assertThat(replaceErr.getScimType()).isEqualTo("mutability");

        List<Map<String, Object>> addTypeOps = List.of(Map.of(
                "op", "add",
                "path", "members[value eq \"" + user.getId() + "\"].type",
                "value", "User"
        ));

        ScimGroup updated = service.patchGroup(workspaceId, groupId, addTypeOps, null);
        assertThat(updated.getMembers()).hasSize(1);
        assertThat(updated.getMembers().get(0).getMemberType()).isEqualTo("User");

        // Now that immutable type is set to "User", adding a conflicting type must fail with 400 mutability
        List<Map<String, Object>> conflictOps = List.of(Map.of(
                "op", "add",
                "path", "members[value eq \"" + user.getId() + "\"].type",
                "value", "Group"
        ));

        ScimException error = catchThrowableOfType(ScimException.class,
                () -> service.patchGroup(workspaceId, groupId, conflictOps, null));

        assertThat(error).isNotNull();
        assertThat(error.getHttpStatus()).isEqualTo(400);
        assertThat(error.getScimType()).isEqualTo("mutability");
    }

    @Test
    // RFC7643-2.4-63934b
    void createPutAndPatchGroup_refOnlyMembersDeduplicationAndConflictValidation() {
        ScimUser user2 = new ScimUser();
        user2.setId(UUID.randomUUID());
        user2.setWorkspace(workspace);
        user2.setUserName("member2");
        user2.setDisplayName("Member Two");

        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.findByIdAndWorkspaceId(user.getId(), workspaceId)).thenReturn(Optional.of(user));
        when(userRepository.findByIdAndWorkspaceId(user2.getId(), workspaceId)).thenReturn(Optional.of(user2));
        when(groupRepository.save(any(ScimGroup.class))).thenAnswer(i -> {
            ScimGroup g = i.getArgument(0);
            if (g.getId() == null) g.setId(groupId);
            g.setCreatedAt(java.time.Instant.now());
            g.setLastModified(g.getCreatedAt());
            return g;
        });

        // 1. POST with $ref-only cross-version duplicate entries -> deduplicated to 1 resolved User member
        Map<String, Object> createInput = Map.of(
                "displayName", "RefGroup",
                "members", List.of(
                        Map.of("$ref", "https://old.example.com/scim/v1/Users/" + user.getId()),
                        Map.of("$ref", "/Users/" + user.getId())
                )
        );
        ScimGroup created = service.createGroup(workspaceId, createInput);
        assertThat(created.getMembers()).hasSize(1);
        assertThat(created.getMembers().get(0).getMemberValue()).isEqualTo(user.getId());
        assertThat(created.getMembers().get(0).getMemberType()).isEqualTo("User");
        assertThat(created.getMembers().get(0).getDisplay()).isEqualTo("Member One");

        Map<String, Object> mapped = de.palsoftware.scim.server.impl.scim.mapper.ScimGroupMapper.toScimResponse(
                created, "https://scim.example.com/ws/" + workspaceId + "/scim/v2");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> members = (List<Map<String, Object>>) mapped.get("members");
        assertThat(members.get(0))
                .containsEntry("value", user.getId().toString())
                .containsEntry("$ref", "https://scim.example.com/ws/" + workspaceId + "/scim/v2/Users/" + user.getId());

        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(created));

        // 2. PATCH add with $ref-only member (relative ../Users/<id>) and PATCH remove with $ref-only member
        ScimGroup afterAdd = service.patchGroup(workspaceId, groupId, List.of(Map.of(
                "op", "add",
                "path", "members",
                "value", List.of(Map.of("$ref", "../Users/" + user2.getId()))
        )), null);
        assertThat(afterAdd.getMembers()).hasSize(2);

        ScimGroup afterRemove = service.patchGroup(workspaceId, groupId, List.of(Map.of(
                "op", "remove",
                "path", "members",
                "value", List.of(Map.of("$ref", "https://legacy.example/scim/v1/Users/" + user.getId()))
        )), null);
        assertThat(afterRemove.getMembers()).hasSize(1);
        assertThat(afterRemove.getMembers().get(0).getMemberValue()).isEqualTo(user2.getId());

        // 3. PUT with $ref-only member
        ScimGroup afterPut = service.replaceGroup(workspaceId, groupId, Map.of(
                "displayName", "RefGroup",
                "members", List.of(Map.of("$ref", "/Users/" + user.getId()))
        ), null);
        assertThat(afterPut.getMembers()).hasSize(1);
        assertThat(afterPut.getMembers().get(0).getMemberValue()).isEqualTo(user.getId());

        // 4. Pre-deduplication conflict validation and non-SCIM URI rejection -> 400 invalidValue
        ScimException dupConflict = catchThrowableOfType(ScimException.class, () -> service.createGroup(workspaceId, Map.of(
                "displayName", "BadDupGroup",
                "members", List.of(
                        Map.of("value", user.getId().toString(), "$ref", "/Users/" + user.getId()),
                        Map.of("value", user.getId().toString(), "$ref", "/Users/" + user2.getId())
                )
        )));
        assertThat(dupConflict).isNotNull();
        assertThat(dupConflict.getHttpStatus()).isEqualTo(400);
        assertThat(dupConflict.getScimType()).isEqualTo("invalidValue");

        ScimException nonScimUri = catchThrowableOfType(ScimException.class, () -> service.patchGroup(workspaceId, groupId, List.of(Map.of(
                "op", "add",
                "path", "members",
                "value", List.of(Map.of("value", user2.getId().toString(), "$ref", "https://example.com/OtherPath/123"))
        )), null));
        assertThat(nonScimUri).isNotNull();
        assertThat(nonScimUri.getHttpStatus()).isEqualTo(400);
        assertThat(nonScimUri.getScimType()).isEqualTo("invalidValue");
    }

    @Test
    void selfMembership_rejectedWith400InvalidValueAcrossCreatePutAndPatch() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(groupRepository.save(any(ScimGroup.class))).thenAnswer(i -> {
            ScimGroup g = i.getArgument(0);
            if (g.getId() == null) {
                g.setId(groupId);
            }
            return g;
        });
        when(groupRepository.findByIdAndWorkspaceId(groupId, workspaceId)).thenReturn(Optional.of(group));

        for (Map<String, Object> selfMember : List.<Map<String, Object>>of(
                Map.<String, Object>of("value", groupId.toString()),
                Map.<String, Object>of("value", groupId.toString(), "type", "Group"),
                Map.<String, Object>of("$ref", "/Groups/" + groupId))) {
            ScimException createEx = catchThrowableOfType(ScimException.class,
                    () -> service.createGroup(workspaceId, Map.of("displayName", "SelfCreate", "members", List.of(selfMember))));
            assertThat(createEx).isNotNull();
            assertThat(createEx.getHttpStatus()).isEqualTo(400);
            assertThat(createEx.getScimType()).isEqualTo("invalidValue");

            ScimException putEx = catchThrowableOfType(ScimException.class,
                    () -> service.replaceGroup(workspaceId, groupId, Map.of("displayName", "TestGroup", "members", List.of(selfMember)), null));
            assertThat(putEx).isNotNull();
            assertThat(putEx.getHttpStatus()).isEqualTo(400);
            assertThat(putEx.getScimType()).isEqualTo("invalidValue");

            ScimException patchAddEx = catchThrowableOfType(ScimException.class,
                    () -> service.patchGroup(workspaceId, groupId, List.of(Map.of("op", "add", "path", "members", "value", List.of(selfMember))), null));
            assertThat(patchAddEx).isNotNull();
            assertThat(patchAddEx.getHttpStatus()).isEqualTo(400);
            assertThat(patchAddEx.getScimType()).isEqualTo("invalidValue");

            ScimException patchPathlessEx = catchThrowableOfType(ScimException.class,
                    () -> service.patchGroup(workspaceId, groupId, List.of(Map.of("op", "replace", "value", Map.of("members", List.of(selfMember)))), null));
            assertThat(patchPathlessEx).isNotNull();
            assertThat(patchPathlessEx.getHttpStatus()).isEqualTo(400);
            assertThat(patchPathlessEx.getScimType()).isEqualTo("invalidValue");
        }
    }
}
