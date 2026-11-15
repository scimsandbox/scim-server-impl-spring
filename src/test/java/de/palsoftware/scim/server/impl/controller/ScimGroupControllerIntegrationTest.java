package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.PostgresIntegrationTestSupport;
import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.model.ScimGroupMembership;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.repository.ScimGroupRepository;
import de.palsoftware.scim.server.impl.repository.ScimUserRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.ActiveProfiles;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

@SpringBootTest
@AutoConfigureMockMvc(addFilters = false)
@ActiveProfiles("test")
@TestPropertySource(properties = "ACTUATOR_API_KEY=test-key")
class ScimGroupControllerIntegrationTest extends PostgresIntegrationTestSupport {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ScimGroupRepository groupRepository;

    @Autowired
    private ScimUserRepository userRepository;

    @Autowired
    private WorkspaceRepository workspaceRepository;

    @Test
    void testListGroups_doesNotThrowLazyInitializationException() throws Exception {
        // Create workspace
        Workspace ws = new Workspace();
        ws.setName("test-ws-groups-" + UUID.randomUUID());
        ws.setCreatedByUsername("test-user");
        ws = workspaceRepository.save(ws);

        // Create user
        ScimUser user = new ScimUser();
        user.setWorkspace(ws);
        user.setUserName("member.test");
        user = userRepository.saveAndFlush(user);

        // Create group with lazy collection (members)
        ScimGroup group = new ScimGroup();
        group.setWorkspace(ws);
        group.setDisplayName("Test Group");

        ScimGroupMembership membership = new ScimGroupMembership();
        membership.setGroup(group);
        membership.setMemberValue(user.getId());
        membership.setMemberType("User");
        membership.setDisplay(user.getUserName());
        group.getMembers().add(membership);

        groupRepository.saveAndFlush(group);

        // Perform GET request that triggers mapper outside transaction
        mockMvc.perform(get("/ws/" + ws.getId() + "/scim/v2/Groups"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.Resources[0].members[0].value").value(user.getId().toString()));
    }

    @Test
    void testV5GroupConstraints_rejectSelfMembershipAndAllowMemberReplacementWithoutUniqueViolation() throws Exception {
        Workspace ws = new Workspace();
        ws.setName("test-ws-v5-groups-" + UUID.randomUUID());
        ws.setCreatedByUsername("test-user");
        ws = workspaceRepository.save(ws);

        ScimUser u1 = new ScimUser();
        u1.setWorkspace(ws);
        u1.setUserName("u1.member");
        u1 = userRepository.saveAndFlush(u1);

        ScimUser u2 = new ScimUser();
        u2.setWorkspace(ws);
        u2.setUserName("u2.member");
        u2 = userRepository.saveAndFlush(u2);

        ScimGroup group = new ScimGroup();
        group.setWorkspace(ws);
        group.setDisplayName("Engineering");
        ScimGroupMembership m1 = new ScimGroupMembership();
        m1.setGroup(group);
        m1.setMemberValue(u1.getId());
        m1.setMemberType("User");
        m1.setDisplay(u1.getUserName());
        group.getMembers().add(m1);
        group = groupRepository.saveAndFlush(group);

        String groupsBase = "/ws/" + ws.getId() + "/scim/v2/Groups";
        String bulkPath = "/ws/" + ws.getId() + "/scim/v2/Bulk";

        // 1. PUT self-membership returns 400 invalidValue (not 500 check_violation)
        mockMvc.perform(put(groupsBase + "/" + group.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Group\"],\"displayName\":\"Engineering\",\"members\":[{\"value\":\"" + group.getId() + "\",\"type\":\"Group\"}]}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("invalidValue"));

        // 2. PATCH add self-membership returns 400 invalidValue
        mockMvc.perform(patch(groupsBase + "/" + group.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\"Operations\":[{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"" + group.getId() + "\"}]}]}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("invalidValue"));

        // 3. Bulk POST self-referential bulkId returns per-op 400 invalidValue and cleans up shell
        mockMvc.perform(post(bulkPath)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:BulkRequest\"],\"Operations\":[{\"method\":\"POST\",\"path\":\"/Groups\",\"bulkId\":\"selfGrp\",\"data\":{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Group\"],\"displayName\":\"SelfBulk\",\"members\":[{\"value\":\"bulkId:selfGrp\"}]}}]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.Operations[0].status").value("400"))
                .andExpect(jsonPath("$.Operations[0].response.scimType").value("invalidValue"));

        // 4. PUT and PATCH replacing members while retaining u1 succeeds cleanly against uk_scim_group_memberships_workspace_group_member
        mockMvc.perform(put(groupsBase + "/" + group.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Group\"],\"displayName\":\"Engineering\",\"members\":[{\"value\":\"" + u1.getId() + "\",\"type\":\"User\"},{\"value\":\"" + u2.getId() + "\",\"type\":\"User\"}]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.members.length()").value(2));

        mockMvc.perform(patch(groupsBase + "/" + group.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\"Operations\":[{\"op\":\"replace\",\"path\":\"members\",\"value\":[{\"value\":\"" + u1.getId() + "\",\"type\":\"User\"}]}]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.members.length()").value(1));
    }
}
