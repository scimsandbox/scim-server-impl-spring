package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.PostgresIntegrationTestSupport;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.model.ScimUserEmail;
import de.palsoftware.scim.server.impl.model.Workspace;
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
class ScimUserControllerIntegrationTest extends PostgresIntegrationTestSupport {

    private record JsonFilterFixture(Workspace workspace, ScimUser user1, ScimUser user2) {
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ScimUserRepository userRepository;

    @Autowired
    private WorkspaceRepository workspaceRepository;

    @Test
    void testListUsers_doesNotThrowLazyInitializationException() throws Exception {
        // Create workspace
        Workspace ws = new Workspace();
        ws.setName("test-ws-" + UUID.randomUUID());
        ws.setCreatedByUsername("test-user");
        ws = workspaceRepository.save(ws);

        // Create user with lazy collection
        ScimUser user = new ScimUser();
        user.setWorkspace(ws);
        user.setUserName("lazy.test");
        user.setExternalId("ext1");

        ScimUserEmail email = new ScimUserEmail();
        email.setValue("test@example.com");
        email.setType("work");
        user.getEmails().add(email);

        userRepository.saveAndFlush(user);

        // Perform GET request that triggers mapper outside transaction.
        // addFilters=false bypasses Spring Security so we hit the controller directly.
        mockMvc.perform(get("/ws/" + ws.getId() + "/scim/v2/Users"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.Resources[0].emails[0].value").value("test@example.com"));
    }

    @Test
    void testFilterMultiValuedJsonAttributes() throws Exception {
        JsonFilterFixture fixture = createJsonFilterFixture();
        Workspace ws = fixture.workspace();

        // Test filtering by emails.value eq "user1@work.com"
        mockMvc.perform(get("/ws/" + ws.getId() + "/scim/v2/Users")
                .param("filter", "emails.value eq \"user1@work.com\""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.Resources.length()").value(1))
                .andExpect(jsonPath("$.Resources[0].userName").value("user1"));

        // Test filtering by emails.type eq "home"
        mockMvc.perform(get("/ws/" + ws.getId() + "/scim/v2/Users")
                .param("filter", "emails.type eq \"home\""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.Resources.length()").value(1))
                .andExpect(jsonPath("$.Resources[0].userName").value("user2"));
    }

    @Test
    void testFilterValuePathOnJsonEmails() throws Exception {
        JsonFilterFixture fixture = createJsonFilterFixture();
        Workspace ws = fixture.workspace();

        mockMvc.perform(get("/ws/" + ws.getId() + "/scim/v2/Users")
                .param("filter", "emails[type eq \"work\"]"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.Resources.length()").value(1))
                .andExpect(jsonPath("$.Resources[0].userName").value("user1"));
    }

    private JsonFilterFixture createJsonFilterFixture() {
        Workspace ws = new Workspace();
        ws.setName("test-ws-json-" + UUID.randomUUID());
        ws.setCreatedByUsername("test-user");
        ws = workspaceRepository.save(ws);

        ScimUser user1 = new ScimUser();
        user1.setWorkspace(ws);
        user1.setUserName("user1");
        ScimUserEmail email1 = new ScimUserEmail();
        email1.setValue("user1@work.com");
        email1.setType("work");
        user1.getEmails().add(email1);
        user1 = userRepository.saveAndFlush(user1);

        ScimUser user2 = new ScimUser();
        user2.setWorkspace(ws);
        user2.setUserName("user2");
        ScimUserEmail email2 = new ScimUserEmail();
        email2.setValue("user2@home.com");
        email2.setType("home");
        user2.getEmails().add(email2);
        user2 = userRepository.saveAndFlush(user2);

        return new JsonFilterFixture(ws, user1, user2);
    }
}
