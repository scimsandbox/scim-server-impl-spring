package de.palsoftware.scim.server.impl.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.util.concurrent.RateLimiter;
import de.palsoftware.scim.server.impl.PostgresIntegrationTestSupport;
import de.palsoftware.scim.server.impl.ScimServerApplication;
import de.palsoftware.scim.server.impl.filter.ThrottlingFilter;
import de.palsoftware.scim.server.impl.logging.RequestResponseLoggingFilter;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.model.WorkspaceToken;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceTokenRepository;
import de.palsoftware.scim.server.impl.security.TokenSecurityUtil;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(
        classes = {ScimServerApplication.class, SecurityConfigIntegrationTest.CountingThrottlingConfig.class},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT
)
@AutoConfigureObservability
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "ACTUATOR_API_KEY=test-key",
        "management.server.port=0"
})
class SecurityConfigIntegrationTest extends PostgresIntegrationTestSupport {

    @TestConfiguration
    static class CountingThrottlingConfig {
        static final AtomicInteger PERMIT_ACQUISITIONS = new AtomicInteger();

        @Bean
        @Primary
        ThrottlingFilter countingThrottlingFilter(ObjectMapper objectMapper) {
            RateLimiter delegate = RateLimiter.create(500.0);
            return new ThrottlingFilter(timeout -> {
                PERMIT_ACQUISITIONS.incrementAndGet();
                return delegate.tryAcquire(1);
            }, Duration.ZERO, objectMapper);
        }
    }

    @LocalServerPort
    private int serverPort;

    @LocalManagementPort
    private int managementPort;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private WorkspaceRepository workspaceRepository;

    @Autowired
    private WorkspaceTokenRepository tokenRepository;

    @Autowired
    private FilterRegistrationBean<ThrottlingFilter> disableThrottlingFilterServletRegistration;

    private record WorkspaceAuth(Workspace workspace, String rawToken) {}

    private WorkspaceAuth createAuthenticatedWorkspace() {
        Workspace ws = new Workspace();
        ws.setName("sec-test-ws-" + UUID.randomUUID());
        ws.setCreatedByUsername("test-user");
        ws = workspaceRepository.save(ws);

        String rawToken = UUID.randomUUID().toString();
        WorkspaceToken token = new WorkspaceToken();
        token.setWorkspace(ws);
        token.setName("Test Token");
        token.setTokenHash(TokenSecurityUtil.sha256Hex(rawToken));
        token.setExpiresAt(Instant.now().plus(1, ChronoUnit.DAYS));
        tokenRepository.saveAndFlush(token);
        return new WorkspaceAuth(ws, rawToken);
    }

    @Test
    void testScimUnmappedEndpoints_Return404Not403() {
        WorkspaceAuth auth = createAuthenticatedWorkspace();
        Workspace ws = auth.workspace();

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + auth.rawToken());
        HttpEntity<?> entity = new HttpEntity<>(headers);

        // 1. Test existing endpoint (Users) to verify 200 OK
        ResponseEntity<String> usersResponse = restTemplate.exchange(
                "/ws/" + ws.getId() + "/scim/v2/Users", HttpMethod.GET, entity, String.class);
        assertThat(usersResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

        // 2. Test /Me endpoint -> Expect 501 (Not Implemented, endpoint now exists per RFC 7644 §3.11)
        ResponseEntity<String> meResponse = restTemplate.exchange(
                "/ws/" + ws.getId() + "/scim/v2/Me", HttpMethod.GET, entity, String.class);
        assertThat(meResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_IMPLEMENTED);

        // 3. Test arbitrary unmapped UUID endpoint -> Expect 404 (not 403!)
        ResponseEntity<String> uuidResponse = restTemplate.exchange(
                "/ws/" + ws.getId() + "/scim/v2/" + UUID.randomUUID(), HttpMethod.GET, entity, String.class);
        assertThat(uuidResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);

        // 4. Test arbitrary unmapped string endpoint -> Expect 404 (not 403!)
        ResponseEntity<String> randomResponse = restTemplate.exchange(
                "/ws/" + ws.getId() + "/scim/v2/NonExistentResource", HttpMethod.GET, entity, String.class);
        assertThat(randomResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void actuatorEndpoints_EnforceApiKeyAndHideHealthComponentsWhenUnauthenticated() {
        String mgmtBase = "http://localhost:" + managementPort;

        // 1. Unauthenticated /actuator/health succeeds (200) without exposing components, consuming 0 permits
        int beforeHealth = CountingThrottlingConfig.PERMIT_ACQUISITIONS.get();
        ResponseEntity<String> unauthHealth = restTemplate.getForEntity(mgmtBase + "/actuator/health", String.class);
        assertThat(unauthHealth.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(unauthHealth.getBody()).contains("\"status\":\"UP\"").doesNotContain("\"components\"");
        assertThat(CountingThrottlingConfig.PERMIT_ACQUISITIONS.get() - beforeHealth).isZero();

        // 2. /actuator/prometheus without key -> 401
        ResponseEntity<String> missingKeyResp = restTemplate.getForEntity(mgmtBase + "/actuator/prometheus", String.class);
        assertThat(missingKeyResp.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        // 3. /actuator/prometheus with wrong key -> 401
        HttpHeaders wrongHeaders = new HttpHeaders();
        wrongHeaders.set("X-API-Key", "wrong-key");
        ResponseEntity<String> wrongKeyResp = restTemplate.exchange(
                mgmtBase + "/actuator/prometheus", HttpMethod.GET, new HttpEntity<>(wrongHeaders), String.class);
        assertThat(wrongKeyResp.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        // 4. /actuator/prometheus with valid X-API-Key -> 200 OK
        HttpHeaders validHeaders = new HttpHeaders();
        validHeaders.set("X-API-Key", "test-key");
        ResponseEntity<String> validResp = restTemplate.exchange(
                mgmtBase + "/actuator/prometheus", HttpMethod.GET, new HttpEntity<>(validHeaders), String.class);
        assertThat(validResp.getStatusCode()).isEqualTo(HttpStatus.OK);

        // 5. /actuator/health with valid X-API-Key -> 200 OK with components authorized
        ResponseEntity<String> authHealth = restTemplate.exchange(
                mgmtBase + "/actuator/health", HttpMethod.GET, new HttpEntity<>(validHeaders), String.class);
        assertThat(authHealth.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(authHealth.getBody()).contains("\"components\"");
    }

    @Test
    void throttlingFilter_ExecutesExactlyOncePerScimRequest() {
        assertThat(disableThrottlingFilterServletRegistration.isEnabled()).isFalse();

        WorkspaceAuth auth = createAuthenticatedWorkspace();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + auth.rawToken());

        int before = CountingThrottlingConfig.PERMIT_ACQUISITIONS.get();
        ResponseEntity<String> resp = restTemplate.exchange(
                "/ws/" + auth.workspace().getId() + "/scim/v2/Users",
                HttpMethod.GET,
                new HttpEntity<>(headers),
                String.class);

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(CountingThrottlingConfig.PERMIT_ACQUISITIONS.get() - before).isEqualTo(1);
    }

    @Test
    void nonBulk1MiBCap_RejectsFixedAndChunkedPayloadsWith413_WhileValidBulkWorks() throws Exception {
        WorkspaceAuth auth = createAuthenticatedWorkspace();
        UUID wsId = auth.workspace().getId();

        String oversizedJson = "{\"userName\":\""
                + "a".repeat(RequestResponseLoggingFilter.MAX_NON_BULK_PAYLOAD_SIZE + 512)
                + "\"}";
        byte[] oversized = oversizedJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        HttpClient httpClient = HttpClient.newHttpClient();

        // 1. Non-Bulk POST /Users with Content-Length > 1 MiB -> 413 SCIM Error
        HttpRequest fixedLenReq = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + serverPort + "/ws/" + wsId + "/scim/v2/Users"))
                .header("Authorization", "Bearer " + auth.rawToken())
                .header("Content-Type", "application/scim+json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(oversized))
                .build();
        HttpResponse<String> fixedLenResp = httpClient.send(fixedLenReq, HttpResponse.BodyHandlers.ofString());
        assertThat(fixedLenResp.statusCode()).isEqualTo(413);
        assertThat(fixedLenResp.body())
                .contains("urn:ietf:params:scim:api:messages:2.0:Error")
                .contains("\"status\":\"413\"");

        // 2. Non-Bulk POST /Users with chunked transfer (unknown length via InputStream) > 1 MiB -> 413 SCIM Error
        HttpRequest chunkedReq = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + serverPort + "/ws/" + wsId + "/scim/v2/Users"))
                .header("Authorization", "Bearer " + auth.rawToken())
                .header("Content-Type", "application/scim+json")
                .POST(HttpRequest.BodyPublishers.ofInputStream(() -> new ByteArrayInputStream(oversized)))
                .build();
        HttpResponse<String> chunkedResp = httpClient.send(chunkedReq, HttpResponse.BodyHandlers.ofString());
        assertThat(chunkedResp.statusCode()).isEqualTo(413);
        assertThat(chunkedResp.body())
                .contains("urn:ietf:params:scim:api:messages:2.0:Error")
                .contains("\"status\":\"413\"");

        // 3. Valid Bulk request continues to succeed (200 OK)
        String validBulkJson = """
                {
                  "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                  "Operations": [
                    {
                      "method": "POST",
                      "path": "/Users",
                      "bulkId": "b1",
                      "data": {
                        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                        "userName": "bulk-ok-%s"
                      }
                    }
                  ]
                }
                """.formatted(UUID.randomUUID());
        HttpHeaders bulkHeaders = new HttpHeaders();
        bulkHeaders.set("Authorization", "Bearer " + auth.rawToken());
        bulkHeaders.setContentType(MediaType.parseMediaType("application/scim+json"));
        ResponseEntity<String> bulkResp = restTemplate.exchange(
                "/ws/" + wsId + "/scim/v2/Bulk",
                HttpMethod.POST,
                new HttpEntity<>(validBulkJson, bulkHeaders),
                String.class);
        assertThat(bulkResp.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void over72ByteUtf8PasswordAndDeepFilter_ReturnCleanScim400Responses() {
        WorkspaceAuth auth = createAuthenticatedWorkspace();
        UUID wsId = auth.workspace().getId();

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + auth.rawToken());
        headers.setContentType(MediaType.parseMediaType("application/scim+json"));

        // 1. 25x '€' = 25 chars, 75 UTF-8 bytes -> 400 invalidValue (not 500!)
        String userJson = "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],"
                + "\"userName\":\"utf8pw-" + UUID.randomUUID() + "\","
                + "\"password\":\"" + "€".repeat(25) + "\"}";
        ResponseEntity<String> pwResp = restTemplate.exchange(
                "/ws/" + wsId + "/scim/v2/Users",
                HttpMethod.POST,
                new HttpEntity<>(userJson, headers),
                String.class);
        assertThat(pwResp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(pwResp.getBody()).contains("\"scimType\":\"invalidValue\"");

        // 2. Deeply nested filter -> 400 invalidFilter
        String deepFilter = "(".repeat(25) + "userName eq \"a\"" + ")".repeat(25);
        ResponseEntity<String> filterResp = restTemplate.exchange(
                "/ws/" + wsId + "/scim/v2/Users?filter={filter}",
                HttpMethod.GET,
                new HttpEntity<>(headers),
                String.class,
                deepFilter);
        assertThat(filterResp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(filterResp.getBody()).contains("\"scimType\":\"invalidFilter\"");
    }
}
