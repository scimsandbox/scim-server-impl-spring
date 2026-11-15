package de.palsoftware.scim.server.impl.config;

import de.palsoftware.scim.server.impl.PostgresIntegrationTestSupport;
import de.palsoftware.scim.server.impl.ScimServerApplication;
import de.palsoftware.scim.server.impl.filter.PayloadSizeLimitFilter;
import de.palsoftware.scim.server.impl.filter.ThrottlingFilter;
import de.palsoftware.scim.server.impl.filter.WorkspaceRateLimitFilter;
import de.palsoftware.scim.server.impl.model.ScimRequestLog;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.model.WorkspaceToken;
import de.palsoftware.scim.server.impl.repository.ScimRequestLogRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceTokenRepository;
import de.palsoftware.scim.server.impl.security.TokenSecurityUtil;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.persistence.EntityManagerFactory;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.data.domain.PageRequest;
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
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(
        classes = {ScimServerApplication.class, SecurityConfigIntegrationTest.CountingThrottlingConfig.class},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT
)
@AutoConfigureObservability
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "ACTUATOR_API_KEY=test-key",
        "management.server.port=0",
        "app.rate-limit.requests-per-second=1",
        "app.rate-limit.burst=200",
        "app.rate-limit.per-ip-requests-per-second=0.2",
        "app.rate-limit.per-ip-burst=6",
        "app.rate-limit.unauthenticated-requests-per-second=0.05",
        "app.rate-limit.unauthenticated-burst=24",
        "app.rate-limit.per-workspace-requests-per-second=0.2",
        "app.rate-limit.per-workspace-burst=6",
        "app.rate-limit.wait-timeout=0s",
        "spring.jpa.properties.hibernate.generate_statistics=true"
})
class SecurityConfigIntegrationTest extends PostgresIntegrationTestSupport {

    @TestConfiguration
    static class CountingThrottlingConfig {
        static final AtomicInteger PERMIT_ACQUISITIONS = new AtomicInteger();
        static final AtomicReference<ThrottlingFilter.UnauthenticatedLookupLimiter> UNAUTH_LOOKUP_DELEGATE =
                new AtomicReference<>(ThrottlingFilter.UnauthenticatedLookupLimiter.NOOP);

        @Bean
        ThrottlingFilter.KeyedPermitLimiter countingPermitLimiter(
                @Value("${app.rate-limit.requests-per-second}") double globalRequestsPerSecond,
                @Value("${app.rate-limit.burst:0}") int globalBurst,
                @Value("${app.rate-limit.per-ip-requests-per-second:0}") double perIpRequestsPerSecond,
                @Value("${app.rate-limit.per-ip-burst:0}") int perIpBurst) {
            ThrottlingFilter.KeyedPermitLimiter delegate =
                    ThrottlingFilter.createPreAuthLimiter(
                            globalRequestsPerSecond, globalBurst, perIpRequestsPerSecond, perIpBurst);
            return (key, timeout) -> {
                PERMIT_ACQUISITIONS.incrementAndGet();
                return delegate.tryAcquire(key, timeout);
            };
        }

        @Bean
        ThrottlingFilter.UnauthenticatedLookupLimiter delegatingUnauthenticatedLookupLimiter(
                @Value("${app.rate-limit.requests-per-second}") double globalRequestsPerSecond,
                @Value("${app.rate-limit.burst:0}") int globalBurst,
                @Value("${app.rate-limit.unauthenticated-requests-per-second:0}") double unauthenticatedRequestsPerSecond,
                @Value("${app.rate-limit.unauthenticated-burst:0}") int unauthenticatedBurst,
                @Value("${app.rate-limit.wait-timeout:0s}") Duration waitTimeout) {
            UNAUTH_LOOKUP_DELEGATE.set(ThrottlingFilter.createUnauthenticatedLookupLimiter(
                    globalRequestsPerSecond,
                    globalBurst,
                    unauthenticatedRequestsPerSecond,
                    unauthenticatedBurst,
                    waitTimeout));
            return new ThrottlingFilter.UnauthenticatedLookupLimiter() {
                @Override
                public boolean isKnownActiveToken(String tokenCacheKey) {
                    return UNAUTH_LOOKUP_DELEGATE.get().isKnownActiveToken(tokenCacheKey);
                }

                @Override
                public ThrottlingFilter.AcquireResult tryAcquireLookupPermit() {
                    return UNAUTH_LOOKUP_DELEGATE.get().tryAcquireLookupPermit();
                }

                @Override
                public void onValidTokenLookup(String tokenCacheKey, boolean refundLookupPermit) {
                    UNAUTH_LOOKUP_DELEGATE.get().onValidTokenLookup(tokenCacheKey, refundLookupPermit);
                }

                @Override
                public void evictToken(String tokenCacheKey) {
                    UNAUTH_LOOKUP_DELEGATE.get().evictToken(tokenCacheKey);
                }
            };
        }
    }

    @BeforeEach
    void resetUnauthenticatedLookupLimiter() {
        CountingThrottlingConfig.UNAUTH_LOOKUP_DELEGATE.set(
                ThrottlingFilter.createUnauthenticatedLookupLimiter(1.0, 200, 0.05, 24, Duration.ZERO));
    }

    @LocalServerPort
    private int serverPort;

    @LocalManagementPort
    private int managementPort;

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private WorkspaceRepository workspaceRepository;

    @Autowired
    private WorkspaceTokenRepository tokenRepository;

    @Autowired
    private ScimRequestLogRepository requestLogRepository;

    @Autowired
    private MeterRegistry meterRegistry;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

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
        headers.set("X-Forwarded-For", "198.51.100.10");
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
        assertThat(applicationContext.getBeansOfType(ThrottlingFilter.class)).hasSize(1);
        assertThat(applicationContext.getBeansOfType(WorkspaceRateLimitFilter.class)).hasSize(1);

        WorkspaceAuth auth = createAuthenticatedWorkspace();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + auth.rawToken());
        headers.set("X-Forwarded-For", "198.51.100.11");

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
    void threeTierRateLimiting_BlocksInvalidAndRandomUuidFloodsByIpWithoutLockingOutWorkspace() {
        WorkspaceAuth workspaceA = createAuthenticatedWorkspace();
        WorkspaceAuth workspaceB = createAuthenticatedWorkspace();

        // 1. Outsider IP (203.0.113.99) floods Workspace A with invalid tokens:
        //    drains ONLY that attacker IP's 6-token pre-auth bucket (not Workspace A's bucket!)
        HttpHeaders invalidHeaders = new HttpHeaders();
        invalidHeaders.set("Authorization", "Bearer invalid-flood-token");
        invalidHeaders.set("X-Forwarded-For", "203.0.113.99");
        HttpEntity<?> invalidEntity = new HttpEntity<>(invalidHeaders);

        for (int i = 0; i < 6; i++) {
            ResponseEntity<String> unauthResp = restTemplate.exchange(
                    "/ws/" + workspaceA.workspace().getId() + "/scim/v2/Users",
                    HttpMethod.GET,
                    invalidEntity,
                    String.class);
            assertThat(unauthResp.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
        statistics.clear();
        double throttledYesBefore = meterRegistry.counter("scim.operation.throttled", "state", "yes").count();
        double authUnknownBefore = meterRegistry.counter("scim.operation.authentication", "state", "unknown").count();
        double authFailedBefore = meterRegistry.counter("scim.operation.authentication", "state", "failed").count();

        // Subsequent flood from 203.0.113.99 is rejected pre-auth (429, dynamic Retry-After: 5 for 0.2 RPS) with 0 DB queries
        for (int i = 0; i < 3; i++) {
            ResponseEntity<String> throttledResp = restTemplate.exchange(
                    "/ws/" + workspaceA.workspace().getId() + "/scim/v2/Users",
                    HttpMethod.GET,
                    invalidEntity,
                    String.class);
            assertThat(throttledResp.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
            assertThat(throttledResp.getHeaders().getFirst("Retry-After")).isEqualTo("5");
            assertThat(throttledResp.getBody())
                    .contains("urn:ietf:params:scim:api:messages:2.0:Error")
                    .contains("\"status\":\"429\"");
        }

        assertThat(statistics.getPrepareStatementCount()).isZero();
        assertThat(meterRegistry.counter("scim.operation.throttled", "state", "yes").count() - throttledYesBefore)
                .isEqualTo(3.0);
        assertThat(meterRegistry.counter("scim.operation.authentication", "state", "unknown").count() - authUnknownBefore)
                .isEqualTo(3.0);
        assertThat(meterRegistry.counter("scim.operation.authentication", "state", "failed").count() - authFailedBefore)
                .isZero();

        // 2. Workspace A's legitimate client from another IP (198.51.100.42) is NOT locked out!
        HttpHeaders validHeadersA = new HttpHeaders();
        validHeadersA.set("Authorization", "Bearer " + workspaceA.rawToken());
        validHeadersA.set("X-Forwarded-For", "198.51.100.42");
        ResponseEntity<String> respA = restTemplate.exchange(
                "/ws/" + workspaceA.workspace().getId() + "/scim/v2/Users",
                HttpMethod.GET,
                new HttpEntity<>(validHeadersA),
                String.class);
        assertThat(respA.getStatusCode()).isEqualTo(HttpStatus.OK);

        // 3. Attacker IP (203.0.113.100) rotating random workspace UUIDs is also stopped after 6 requests with 0 DB queries
        HttpHeaders randomUuidHeaders = new HttpHeaders();
        randomUuidHeaders.set("Authorization", "Bearer random-uuid-flood-token");
        randomUuidHeaders.set("X-Forwarded-For", "203.0.113.100");
        HttpEntity<?> randomUuidEntity = new HttpEntity<>(randomUuidHeaders);
        for (int i = 0; i < 6; i++) {
            ResponseEntity<String> r = restTemplate.exchange(
                    "/ws/" + UUID.randomUUID() + "/scim/v2/Users",
                    HttpMethod.GET,
                    randomUuidEntity,
                    String.class);
            assertThat(r.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
        statistics.clear();
        ResponseEntity<String> randomUuidThrottled = restTemplate.exchange(
                "/ws/" + UUID.randomUUID() + "/scim/v2/Users",
                HttpMethod.GET,
                randomUuidEntity,
                String.class);
        assertThat(randomUuidThrottled.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(randomUuidThrottled.getHeaders().getFirst("Retry-After")).isEqualTo("5");
        assertThat(statistics.getPrepareStatementCount()).isZero();

        // 4. Post-auth Tier 3 per-workspace cap enforces Workspace A's 6-token burst across multiple IPs while Workspace B stays 200 OK
        for (int i = 0; i < 5; i++) {
            HttpHeaders nextHeadersA = new HttpHeaders();
            nextHeadersA.set("Authorization", "Bearer " + workspaceA.rawToken());
            nextHeadersA.set("X-Forwarded-For", "198.51.100.43");
            assertThat(restTemplate.exchange(
                    "/ws/" + workspaceA.workspace().getId() + "/scim/v2/Users",
                    HttpMethod.GET,
                    new HttpEntity<>(nextHeadersA),
                    String.class).getStatusCode()).isEqualTo(HttpStatus.OK);
        }
        HttpHeaders freshIpHeadersA = new HttpHeaders();
        freshIpHeadersA.set("Authorization", "Bearer " + workspaceA.rawToken());
        freshIpHeadersA.set("X-Forwarded-For", "198.51.100.44");
        ResponseEntity<String> wsAThrottled = restTemplate.exchange(
                "/ws/" + workspaceA.workspace().getId() + "/scim/v2/Users",
                HttpMethod.GET,
                new HttpEntity<>(freshIpHeadersA),
                String.class);
        assertThat(wsAThrottled.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(wsAThrottled.getHeaders().getFirst("Retry-After")).isEqualTo("5");

        HttpHeaders validHeadersB = new HttpHeaders();
        validHeadersB.set("Authorization", "Bearer " + workspaceB.rawToken());
        validHeadersB.set("X-Forwarded-For", "198.51.100.44");
        ResponseEntity<String> respB = restTemplate.exchange(
                "/ws/" + workspaceB.workspace().getId() + "/scim/v2/Users",
                HttpMethod.GET,
                new HttpEntity<>(validHeadersB),
                String.class);
        assertThat(respB.getStatusCode()).isEqualTo(HttpStatus.OK);

        // 5. Distributed invalid-token flood across 10 distinct IPs (198.18.0.1..198.18.0.10 x 4 = 40 requests,
        //    each IP under per-ip-burst=6):
        //    With 12 of 24 unauthenticated lookup permits already used in Steps 1 & 3 (and workspaceA + workspaceB
        //    warmed in Steps 2 & 4 with their cold-miss permits refunded), the first 12 distributed requests
        //    return 401 and the remaining 28 return 429 with 0 SQL statements prepared!
        int distributedAttempt = 0;
        for (int ipIdx = 1; ipIdx <= 10; ipIdx++) {
            HttpHeaders distributedInvalidHeaders = new HttpHeaders();
            distributedInvalidHeaders.set("Authorization", "Bearer distributed-bad-" + ipIdx);
            distributedInvalidHeaders.set("X-Forwarded-For", "198.18.0." + ipIdx);
            HttpEntity<?> distributedInvalidEntity = new HttpEntity<>(distributedInvalidHeaders);
            for (int reqIdx = 0; reqIdx < 4; reqIdx++) {
                distributedAttempt++;
                if (distributedAttempt == 13) {
                    statistics.clear();
                }
                ResponseEntity<String> distResp = restTemplate.exchange(
                        "/ws/" + workspaceB.workspace().getId() + "/scim/v2/Users",
                        HttpMethod.GET,
                        distributedInvalidEntity,
                        String.class);
                if (distributedAttempt <= 12) {
                    assertThat(distResp.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
                } else {
                    assertThat(distResp.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
                    // 0.05 RPS (1 token per 20s) yields Retry-After=20s at 0ms elapsed (immune to multi-second CI stalls)
                    assertThat(Integer.parseInt(distResp.getHeaders().getFirst("Retry-After"))).isBetween(10, 20);
                }
            }
        }
        assertThat(statistics.getPrepareStatementCount()).isZero();

        // Warm Workspace B STILL bypasses the exhausted unauthenticated lookup bucket and gets 200 OK!
        HttpHeaders postFloodHeadersB = new HttpHeaders();
        postFloodHeadersB.set("Authorization", "Bearer " + workspaceB.rawToken());
        postFloodHeadersB.set("X-Forwarded-For", "198.51.100.45");
        ResponseEntity<String> postFloodRespB = restTemplate.exchange(
                "/ws/" + workspaceB.workspace().getId() + "/scim/v2/Users",
                HttpMethod.GET,
                new HttpEntity<>(postFloodHeadersB),
                String.class);
        assertThat(postFloodRespB.getStatusCode()).isEqualTo(HttpStatus.OK);

        // Revoking Workspace B's token in PostgreSQL takes effect on the VERY NEXT request (401, 0 ms stale window)
        // AND evicts Workspace B's token from verifiedTokenHashes so the subsequent request gets 429 with 0 SQL!
        WorkspaceToken tokenEntityB = tokenRepository
                .findByTokenHashAndNotRevoked(TokenSecurityUtil.sha256Hex(workspaceB.rawToken()))
                .orElseThrow();
        tokenEntityB.setRevoked(true);
        tokenRepository.saveAndFlush(tokenEntityB);

        HttpHeaders revokedHeadersB = new HttpHeaders();
        revokedHeadersB.set("Authorization", "Bearer " + workspaceB.rawToken());
        revokedHeadersB.set("X-Forwarded-For", "198.51.100.46");
        ResponseEntity<String> firstRevokedRespB = restTemplate.exchange(
                "/ws/" + workspaceB.workspace().getId() + "/scim/v2/Users",
                HttpMethod.GET,
                new HttpEntity<>(revokedHeadersB),
                String.class);
        assertThat(firstRevokedRespB.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        statistics.clear();
        ResponseEntity<String> secondRevokedRespB = restTemplate.exchange(
                "/ws/" + workspaceB.workspace().getId() + "/scim/v2/Users",
                HttpMethod.GET,
                new HttpEntity<>(revokedHeadersB),
                String.class);
        assertThat(secondRevokedRespB.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(Integer.parseInt(secondRevokedRespB.getHeaders().getFirst("Retry-After"))).isBetween(10, 20);
        assertThat(statistics.getPrepareStatementCount()).isZero();
    }

    @Test
    void payload1MiBCap_ProtectsPreAuthFormPutAndLogsAuthenticated413ResponsesIncludingBulk() throws Exception {
        WorkspaceAuth auth = createAuthenticatedWorkspace();
        UUID wsId = auth.workspace().getId();

        String oversizedJson = "{\"userName\":\""
                + "a".repeat(PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES + 512)
                + "\"}";
        byte[] oversized = oversizedJson.getBytes(StandardCharsets.UTF_8);

        String oversizedBulkJson = "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:BulkRequest\"],"
                + "\"Operations\":[{\"method\":\"POST\",\"path\":\"/Users\",\"bulkId\":\"b1\","
                + "\"data\":{\"userName\":\"" + "b".repeat(PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES + 512) + "\"}}]}";
        byte[] oversizedBulk = oversizedBulkJson.getBytes(StandardCharsets.UTF_8);

        HttpClient httpClient = HttpClient.newHttpClient();

        // 0. Unauthenticated chunked PUT with application/x-www-form-urlencoded > 1 MiB:
        //    FormContentFilter is disabled so nothing reads the pre-auth stream, returning 401 with 0 request logs!
        byte[] oversizedForm = ("field=" + "x".repeat(PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES + 65_536))
                .getBytes(StandardCharsets.UTF_8);
        HttpRequest unauthFormPut = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + serverPort + "/ws/" + wsId + "/scim/v2/Users/" + UUID.randomUUID()))
                .header("X-Forwarded-For", "198.51.100.50")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .PUT(HttpRequest.BodyPublishers.ofInputStream(() -> new ByteArrayInputStream(oversizedForm)))
                .build();
        HttpResponse<String> unauthFormResp = httpClient.send(unauthFormPut, HttpResponse.BodyHandlers.ofString());
        assertThat(unauthFormResp.statusCode()).isEqualTo(401);
        assertThat(requestLogRepository.findByWorkspace_IdOrderByCreatedAtDesc(wsId, PageRequest.of(0, 10)).getContent())
                .isEmpty();

        // 1. Non-Bulk POST /Users with Content-Length > 1 MiB -> 413 SCIM Error + logged in scim_request_logs
        HttpRequest fixedLenReq = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + serverPort + "/ws/" + wsId + "/scim/v2/Users"))
                .header("Authorization", "Bearer " + auth.rawToken())
                .header("X-Forwarded-For", "198.51.100.51")
                .header("Content-Type", "application/scim+json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(oversized))
                .build();
        HttpResponse<String> fixedLenResp = httpClient.send(fixedLenReq, HttpResponse.BodyHandlers.ofString());
        assertThat(fixedLenResp.statusCode()).isEqualTo(413);
        assertThat(fixedLenResp.body())
                .contains("urn:ietf:params:scim:api:messages:2.0:Error")
                .contains("\"status\":\"413\"");

        // 2. Non-Bulk POST /Users with chunked transfer (unknown length via InputStream) > 1 MiB -> 413 SCIM Error + logged
        HttpRequest chunkedReq = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + serverPort + "/ws/" + wsId + "/scim/v2/Users"))
                .header("Authorization", "Bearer " + auth.rawToken())
                .header("X-Forwarded-For", "198.51.100.51")
                .header("Content-Type", "application/scim+json")
                .POST(HttpRequest.BodyPublishers.ofInputStream(() -> new ByteArrayInputStream(oversized)))
                .build();
        HttpResponse<String> chunkedResp = httpClient.send(chunkedReq, HttpResponse.BodyHandlers.ofString());
        assertThat(chunkedResp.statusCode()).isEqualTo(413);
        assertThat(chunkedResp.body())
                .contains("urn:ietf:params:scim:api:messages:2.0:Error")
                .contains("\"status\":\"413\"");

        // 3. Oversized POST /Bulk (both fixed Content-Length > 1 MiB and chunked > 1 MiB) -> 413 SCIM Error + logged
        HttpRequest fixedBulkReq = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + serverPort + "/ws/" + wsId + "/scim/v2/Bulk"))
                .header("Authorization", "Bearer " + auth.rawToken())
                .header("X-Forwarded-For", "198.51.100.51")
                .header("Content-Type", "application/scim+json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(oversizedBulk))
                .build();
        HttpResponse<String> fixedBulkResp = httpClient.send(fixedBulkReq, HttpResponse.BodyHandlers.ofString());
        assertThat(fixedBulkResp.statusCode()).isEqualTo(413);
        assertThat(fixedBulkResp.body()).contains("maxPayloadSize");

        HttpRequest chunkedBulkReq = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + serverPort + "/ws/" + wsId + "/scim/v2/Bulk"))
                .header("Authorization", "Bearer " + auth.rawToken())
                .header("X-Forwarded-For", "198.51.100.51")
                .header("Content-Type", "application/scim+json")
                .POST(HttpRequest.BodyPublishers.ofInputStream(() -> new ByteArrayInputStream(oversizedBulk)))
                .build();
        HttpResponse<String> chunkedBulkResp = httpClient.send(chunkedBulkReq, HttpResponse.BodyHandlers.ofString());
        assertThat(chunkedBulkResp.statusCode()).isEqualTo(413);
        assertThat(chunkedBulkResp.body()).contains("maxPayloadSize");

        List<ScimRequestLog> saved413Logs = requestLogRepository
                .findByWorkspace_IdOrderByCreatedAtDesc(wsId, PageRequest.of(0, 10))
                .getContent();
        assertThat(saved413Logs).hasSize(4);
        assertThat(saved413Logs).allSatisfy(entry -> {
            assertThat(entry.getStatus()).isEqualTo(413);
            assertThat(entry.getResponseBody()).contains("\"status\":\"413\"");
        });

        // 4. Valid Bulk request continues to succeed (200 OK)
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
        bulkHeaders.set("X-Forwarded-For", "198.51.100.51");
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
        headers.set("X-Forwarded-For", "198.51.100.60");
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
