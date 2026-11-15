package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.model.ScimGroupMembership;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.repository.ScimGroupMembershipRepository;
import de.palsoftware.scim.server.impl.repository.ScimUserRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.model.ScimUserEmail;
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
    @SuppressWarnings("unchecked")
    void listUsers_ascending_usesNullsLast() {
        when(userRepository.count(org.mockito.ArgumentMatchers.<Specification<ScimUser>>any())).thenReturn(1L);
        when(userRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(user)));

        service.listUsers(workspaceId, null, "title", "ascending", 1, 10);

        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(userRepository).findAll(any(Specification.class), pageableCaptor.capture());
        Sort sort = pageableCaptor.getValue().getSort();
        Sort.Order order = sort.getOrderFor("title");
        assertThat(order).isNotNull();
        assertThat(order.isAscending()).isTrue();
        assertThat(order.isIgnoreCase()).isTrue();
        assertThat(order.getNullHandling()).isEqualTo(Sort.NullHandling.NULLS_LAST);
    }

    @Test
    @SuppressWarnings("unchecked")
    void listUsers_caseExactExternalId_doesNotIgnoreCase() {
        when(userRepository.count(org.mockito.ArgumentMatchers.<Specification<ScimUser>>any())).thenReturn(1L);
        when(userRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(user)));

        service.listUsers(workspaceId, null, "externalId", "ascending", 1, 10);

        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(userRepository).findAll(any(Specification.class), pageableCaptor.capture());
        Sort.Order order = pageableCaptor.getValue().getSort().getOrderFor("externalId");
        assertThat(order).isNotNull();
        assertThat(order.isIgnoreCase()).isFalse();
        assertThat(order.getNullHandling()).isEqualTo(Sort.NullHandling.NULLS_LAST);
    }

    @Test
    @SuppressWarnings("unchecked")
    void listUsers_descending_usesNullsFirst() {
        when(userRepository.count(org.mockito.ArgumentMatchers.<Specification<ScimUser>>any())).thenReturn(1L);
        when(userRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(user)));

        service.listUsers(workspaceId, null, "title", "descending", 1, 10);

        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(userRepository).findAll(any(Specification.class), pageableCaptor.capture());
        Sort sort = pageableCaptor.getValue().getSort();
        Sort.Order order = sort.getOrderFor("title");
        assertThat(order).isNotNull();
        assertThat(order.isDescending()).isTrue();
        assertThat(order.getNullHandling()).isEqualTo(Sort.NullHandling.NULLS_FIRST);
    }

    @Test
    @SuppressWarnings("unchecked")
    void listUsers_sortByEmails_ascending() {
        ScimUser u1 = new ScimUser();
        u1.setId(UUID.randomUUID());
        u1.setUserName("user1");
        ScimUserEmail e1Primary = new ScimUserEmail();
        e1Primary.setValue("b_primary@example.com");
        e1Primary.setPrimaryFlag(true);
        ScimUserEmail e1Secondary = new ScimUserEmail();
        e1Secondary.setValue("a_secondary@example.com");
        e1Secondary.setPrimaryFlag(false);
        u1.setEmails(List.of(e1Primary, e1Secondary));

        ScimUser u2 = new ScimUser();
        u2.setId(UUID.randomUUID());
        u2.setUserName("user2");
        ScimUserEmail e2First = new ScimUserEmail();
        e2First.setValue("a_first@example.com");
        e2First.setPrimaryFlag(false);
        u2.setEmails(List.of(e2First));

        ScimUser u3 = new ScimUser();
        u3.setId(UUID.randomUUID());
        u3.setUserName("user3");
        u3.setEmails(Collections.emptyList());

        when(userRepository.findAll(any(Specification.class))).thenReturn(List.of(u1, u2, u3));

        Map<String, Object> response = service.listUsers(workspaceId, null, "emails", "ascending", 1, 10);

        assertThat(response).containsEntry("totalResults", 3L).containsEntry("itemsPerPage", 3);
        List<ScimUser> resources = (List<ScimUser>) response.get("Resources");
        // u2 ("a_first") should come before u1 ("b_primary"), and u3 (no email) should be last
        assertThat(resources).containsExactly(u2, u1, u3);
    }

    @Test
    @SuppressWarnings("unchecked")
    void listUsers_sortByEmails_descending() {
        ScimUser u1 = new ScimUser();
        u1.setId(UUID.randomUUID());
        u1.setUserName("user1");
        ScimUserEmail e1 = new ScimUserEmail();
        e1.setValue("b@example.com");
        e1.setPrimaryFlag(true);
        u1.setEmails(List.of(e1));

        ScimUser u2 = new ScimUser();
        u2.setId(UUID.randomUUID());
        u2.setUserName("user2");
        ScimUserEmail e2 = new ScimUserEmail();
        e2.setValue("a@example.com");
        e2.setPrimaryFlag(true);
        u2.setEmails(List.of(e2));

        ScimUser u3 = new ScimUser();
        u3.setId(UUID.randomUUID());
        u3.setUserName("user3");
        u3.setEmails(Collections.emptyList());

        when(userRepository.findAll(any(Specification.class))).thenReturn(List.of(u1, u2, u3));

        Map<String, Object> response = service.listUsers(workspaceId, null, "emails.value", "descending", 1, 10);

        assertThat(response).containsEntry("totalResults", 3L).containsEntry("itemsPerPage", 3);
        List<ScimUser> resources = (List<ScimUser>) response.get("Resources");
        // Nulls come first on descending, followed by b then a
        assertThat(resources).containsExactly(u3, u1, u2);
    }

    @Test
    @SuppressWarnings("unchecked")
    void listUsers_sortByEmails_pagination() {
        ScimUser u1 = new ScimUser();
        u1.setId(UUID.randomUUID());
        u1.setUserName("user1");
        ScimUserEmail e1 = new ScimUserEmail();
        e1.setValue("b@example.com");
        u1.setEmails(List.of(e1));

        ScimUser u2 = new ScimUser();
        u2.setId(UUID.randomUUID());
        u2.setUserName("user2");
        ScimUserEmail e2 = new ScimUserEmail();
        e2.setValue("a@example.com");
        u2.setEmails(List.of(e2));

        ScimUser u3 = new ScimUser();
        u3.setId(UUID.randomUUID());
        u3.setUserName("user3");
        u3.setEmails(Collections.emptyList());

        when(userRepository.findAll(any(Specification.class))).thenReturn(List.of(u1, u2, u3));

        // startIndex 2, count 1 -> should return 2nd item (u1)
        Map<String, Object> response = service.listUsers(workspaceId, null, "emails", "ascending", 2, 1);

        assertThat(response).containsEntry("totalResults", 3L).containsEntry("startIndex", 2).containsEntry("itemsPerPage", 1);
        List<ScimUser> resources = (List<ScimUser>) response.get("Resources");
        assertThat(resources).containsExactly(u1);
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
    void replaceUser_wildcardIfMatch_success() {
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.of(user));
        when(userRepository.save(any(ScimUser.class))).thenReturn(user);
        Map<String, Object> input = Map.of("userName", "testuser", "displayName", "Replaced Wildcard");

        ScimUser result = service.replaceUser(workspaceId, userId, input, "*");

        assertThat(result).isNotNull();
        verify(userRepository).save(user);
        assertThat(user.getDisplayName()).isEqualTo("Replaced Wildcard");
    }

    @Test
    void patchUser_eTagMismatch_throwsError() {
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.of(user));
        
        ScimException error = catchThrowableOfType(ScimException.class, () -> service.patchUser(workspaceId, userId, Collections.emptyList(), "W/\"999\""));
        
        assertThat(error).isNotNull();
        assertThat(error.getHttpStatus()).isEqualTo(412);
    }

    @Test
    void patchUser_wildcardIfMatch_success() {
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.of(user));
        when(userRepository.save(any(ScimUser.class))).thenReturn(user);

        List<Map<String, Object>> ops = List.of(Map.of("op", "replace", "path", "displayName", "value", "Patched Wildcard"));

        ScimUser result = service.patchUser(workspaceId, userId, ops, "*");

        assertThat(result).isNotNull();
        verify(userRepository).save(user);
        assertThat(user.getDisplayName()).isEqualTo("Patched Wildcard");
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

        verify(membershipRepository).deleteByMemberValueAndWorkspaceId(userId, workspaceId);
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

        when(membershipRepository.findByMemberValueAndWorkspaceId(userId, workspaceId)).thenReturn(List.of(membership));

        List<Map<String, Object>> groups = service.getUserGroups(workspaceId, userId, "http://localhost");

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

        when(membershipRepository.findByMemberValueInAndWorkspaceId(List.of(userId), workspaceId))
                .thenReturn(List.of(membership));

        Map<UUID, List<Map<String, Object>>> batchMap = service.getUserGroupsBatch(workspaceId, List.of(userId), "http://loc");

        assertThat(batchMap).containsKey(userId);
        List<Map<String, Object>> userList = batchMap.get(userId);
        assertThat(userList).hasSize(1);
        assertThat(userList.get(0))
            .containsEntry("value", groupId.toString())
            .containsEntry("display", "Batch Group")
            .containsEntry("$ref", "http://loc/Groups/" + groupId);
    }

    @Test
    void createUser_deduplicatesEmailsAndMergesPrimaryFlag() {
        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.save(any(ScimUser.class))).thenAnswer(i -> {
            ScimUser u = i.getArgument(0);
            u.setId(userId);
            return u;
        });

        Map<String, Object> input = Map.of(
            "userName", "dedupuser",
            "emails", List.of(
                Map.of("value", "dup@example.com", "type", "work", "primary", false),
                Map.of("value", "DUP@EXAMPLE.COM", "type", "WORK", "primary", true)
            )
        );

        ScimUser result = service.createUser(workspaceId, input);

        assertThat(result.getEmails()).hasSize(1);
        assertThat(result.getEmails().get(0).getValue()).isEqualTo("dup@example.com");
        assertThat(result.getEmails().get(0).isPrimaryFlag()).isTrue();
    }

    @Test
    void createUser_resolvesEnterpriseManagerDisplayInSameWorkspace() {
        UUID mgrId = UUID.randomUUID();
        ScimUser manager = new ScimUser();
        manager.setId(mgrId);
        manager.setWorkspace(workspace);
        manager.setUserName("boss");
        manager.setDisplayName("Boss Person");

        when(workspaceRepository.findById(workspaceId)).thenReturn(Optional.of(workspace));
        when(userRepository.findByIdAndWorkspaceId(mgrId, workspaceId)).thenReturn(Optional.of(manager));
        when(userRepository.save(any(ScimUser.class))).thenAnswer(i -> i.getArgument(0));

        Map<String, Object> input = Map.of(
                "userName", "report",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", Map.of(
                        "manager", Map.of("value", mgrId.toString(), "displayName", "Forged Client Name")
                )
        );

        ScimUser created = service.createUser(workspaceId, input);
        assertThat(created.getEnterpriseManagerValue()).isEqualTo(mgrId.toString());
        assertThat(created.getEnterpriseManagerDisplay()).isEqualTo("Boss Person");
    }

    @Test
    void patchUser_noopDoesNotSaveOrBumpVersion() {
        user.setDisplayName("Same Name");
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.of(user));

        List<Map<String, Object>> ops = List.of(
                Map.of("op", "replace", "path", "displayName", "value", "Same Name")
        );

        ScimUser result = service.patchUser(workspaceId, userId, ops, null);
        assertThat(result).isSameAs(user);
        org.mockito.Mockito.verify(userRepository, org.mockito.Mockito.never()).save(any());
    }

    @Test
    void patchUser_removeUserName_throwsMutability() {
        when(userRepository.findByIdAndWorkspaceId(userId, workspaceId)).thenReturn(Optional.of(user));

        List<Map<String, Object>> ops = List.of(Map.of("op", "remove", "path", "userName"));
        ScimException error = catchThrowableOfType(ScimException.class,
                () -> service.patchUser(workspaceId, userId, ops, null));

        assertThat(error).isNotNull();
        assertThat(error.getHttpStatus()).isEqualTo(400);
        assertThat(error.getScimType()).isEqualTo("mutability");
    }

    @Test
    @SuppressWarnings("unchecked")
    void listUsers_multiValuedFilterUsesInMemoryEvaluationAndSkipsGroupBatchWhenNotReferenced() {
        ScimUser matchingUser = new ScimUser();
        matchingUser.setId(UUID.randomUUID());
        matchingUser.setWorkspace(workspace);
        matchingUser.setUserName("alice");
        matchingUser.setUserType("Employee");
        de.palsoftware.scim.server.impl.model.ScimUserEmail workEmail =
                new de.palsoftware.scim.server.impl.model.ScimUserEmail();
        workEmail.setValue("alice@example.com");
        workEmail.setType("work");
        matchingUser.setEmails(new java.util.ArrayList<>(List.of(workEmail)));

        ScimUser nonMatchingUser = new ScimUser();
        nonMatchingUser.setId(UUID.randomUUID());
        nonMatchingUser.setWorkspace(workspace);
        nonMatchingUser.setUserName("bob");
        nonMatchingUser.setUserType("Employee");
        de.palsoftware.scim.server.impl.model.ScimUserEmail homeEmailWithWorkInValue =
                new de.palsoftware.scim.server.impl.model.ScimUserEmail();
        homeEmailWithWorkInValue.setValue("work@example.com");
        homeEmailWithWorkInValue.setType("home");
        nonMatchingUser.setEmails(new java.util.ArrayList<>(List.of(homeEmailWithWorkInValue)));

        when(userRepository.findAll(any(org.springframework.data.jpa.domain.Specification.class),
                any(org.springframework.data.domain.Sort.class)))
                .thenReturn(List.of(matchingUser, nonMatchingUser));

        Map<String, Object> page = service.listUsers(
                workspaceId, "userType eq \"Employee\" and emails.type eq \"work\"",
                "userName", "ascending", 1, 10);

        assertThat((List<ScimUser>) page.get("Resources")).containsExactly(matchingUser);
        assertThat(page.get("totalResults")).isEqualTo(1L);
        org.mockito.Mockito.verify(membershipRepository, org.mockito.Mockito.never())
                .findByMemberValueInAndWorkspaceId(any(), any());
    }

    @Test
    void scimUserMutableState_deepCopiesAndDetectsMutations() {
        ScimUser original = new ScimUser();
        original.setUserName("alice");
        original.setDisplayName("Alice");
        de.palsoftware.scim.server.impl.model.ScimUserEmail email =
                new de.palsoftware.scim.server.impl.model.ScimUserEmail();
        email.setValue("alice@example.com");
        email.setType("work");
        original.setEmails(new java.util.ArrayList<>(List.of(email)));

        ScimUser snapshot = new ScimUser();
        snapshot.applyMutableStateFrom(original);

        assertThat(original.hasSameMutableState(snapshot)).isTrue();

        // Mutating an element inside original's collection must not affect snapshot
        original.getEmails().get(0).setType("home");
        assertThat(original.hasSameMutableState(snapshot)).isFalse();
        assertThat(snapshot.getEmails().get(0).getType()).isEqualTo("work");
    }

    @Test
    void groupMembershipOperations_AreStrictlyScopedByWorkspaceId() {
        UUID otherWorkspaceId = UUID.randomUUID();
        when(membershipRepository.findByMemberValueAndWorkspaceId(userId, workspaceId))
                .thenReturn(Collections.emptyList());

        List<Map<String, Object>> groupsInWs = service.getUserGroups(workspaceId, userId, "http://localhost");
        assertThat(groupsInWs).isEmpty();
        verify(membershipRepository).findByMemberValueAndWorkspaceId(userId, workspaceId);
        org.mockito.Mockito.verify(membershipRepository, org.mockito.Mockito.never())
                .findByMemberValueAndWorkspaceId(userId, otherWorkspaceId);
    }
}
