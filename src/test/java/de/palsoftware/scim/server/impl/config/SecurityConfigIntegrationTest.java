package de.palsoftware.scim.server.impl.config;

import de.palsoftware.scim.server.impl.PostgresIntegrationTestSupport;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.model.WorkspaceToken;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceTokenRepository;
import de.palsoftware.scim.server.impl.security.TokenSecurityUtil;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@TestPropertySource(properties = "ACTUATOR_API_KEY=test-key")
class SecurityConfigIntegrationTest extends PostgresIntegrationTestSupport {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private WorkspaceRepository workspaceRepository;

    @Autowired
    private WorkspaceTokenRepository tokenRepository;

    @Test
    void testScimUnmappedEndpoints_Return404Not403() {
        // 1. Create a workspace
        Workspace ws = new Workspace();
        ws.setName("sec-test-ws-" + UUID.randomUUID());
        ws.setCreatedByUsername("test-user");
        ws = workspaceRepository.save(ws);

        // 2. Create a valid token manually
        String rawToken = UUID.randomUUID().toString();
        String tokenHash = TokenSecurityUtil.sha256Hex(rawToken);

        WorkspaceToken token = new WorkspaceToken();
        token.setWorkspace(ws);
        token.setName("Test Token");
        token.setTokenHash(tokenHash);
        token.setExpiresAt(Instant.now().plus(1, ChronoUnit.DAYS));
        tokenRepository.saveAndFlush(token);

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + rawToken);
        HttpEntity<?> entity = new HttpEntity<>(headers);

        // 3. Test existing endpoint (Users) to verify 200 OK
        ResponseEntity<String> usersResponse = restTemplate.exchange(
                "/ws/" + ws.getId() + "/scim/v2/Users", HttpMethod.GET, entity, String.class);
        assertThat(usersResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

        // 4. Test /Me endpoint -> Expect 501 (Not Implemented, endpoint now exists per RFC 7644 §3.11)
        ResponseEntity<String> meResponse = restTemplate.exchange(
                "/ws/" + ws.getId() + "/scim/v2/Me", HttpMethod.GET, entity, String.class);
        assertThat(meResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_IMPLEMENTED);

        // 5. Test arbitrary unmapped UUID endpoint -> Expect 404 (not 403!)
        ResponseEntity<String> uuidResponse = restTemplate.exchange(
                "/ws/" + ws.getId() + "/scim/v2/" + UUID.randomUUID(), HttpMethod.GET, entity, String.class);
        assertThat(uuidResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);

        // 6. Test arbitrary unmapped string endpoint -> Expect 404 (not 403!)
        ResponseEntity<String> randomResponse = restTemplate.exchange(
                "/ws/" + ws.getId() + "/scim/v2/NonExistentResource", HttpMethod.GET, entity, String.class);
        assertThat(randomResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }
}
