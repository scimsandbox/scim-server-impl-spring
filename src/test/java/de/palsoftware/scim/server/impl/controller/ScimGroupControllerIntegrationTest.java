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

import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.ActiveProfiles;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
}
