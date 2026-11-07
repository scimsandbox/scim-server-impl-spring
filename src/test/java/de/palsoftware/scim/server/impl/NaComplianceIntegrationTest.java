package de.palsoftware.scim.server.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.entity.ScimAsyncEvent;
import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.model.WorkspaceToken;
import de.palsoftware.scim.server.impl.repository.ScimAsyncEventRepository;
import de.palsoftware.scim.server.impl.repository.ScimGroupRepository;
import de.palsoftware.scim.server.impl.repository.ScimUserRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceTokenRepository;
import de.palsoftware.scim.server.impl.scim.error.ScimExceptionHandler;
import de.palsoftware.scim.server.impl.scim.mapper.ScimUserMapper;
import de.palsoftware.scim.server.impl.scim.pagination.ScimCursorCodec;
import de.palsoftware.scim.server.impl.scim.pagination.ScimCursorTestHelper;
import de.palsoftware.scim.server.impl.security.TokenSecurityUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.TransactionSystemException;

import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end PostgreSQL white-box integration tests covering server-applicable {@code na}
 * RFC requirements across RFC 7643, RFC 7644, RFC 9865, and RFC 9967.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "ACTUATOR_API_KEY=test-key",
        "app.rate-limit.requests-per-second=10000"
})
class NaComplianceIntegrationTest extends PostgresIntegrationTestSupport {

    private static final String SCIM_CONTENT_TYPE = "application/scim+json";
    private static final String PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
    private static final String BULK_REQUEST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
    private static final String SEARCH_REQUEST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:SearchRequest";
    private static final String ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
    private static final String DB_PASSWORD_SECRET = "scim_playground";

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private WorkspaceRepository workspaceRepository;

    @Autowired
    private WorkspaceTokenRepository tokenRepository;

    @Autowired
    private ScimUserRepository userRepository;

    @Autowired
    private ScimGroupRepository groupRepository;

    @Autowired
    private ScimAsyncEventRepository asyncEventRepository;

    @Autowired
    private ScimExceptionHandler exceptionHandler;

    private Workspace workspaceA;
    private Workspace workspaceB;
    private String rawTokenA;
    private String rawTokenB;
    private WorkspaceToken tokenA;
    private WorkspaceToken tokenB;

    @BeforeEach
    void setUp() {
        workspaceA = createWorkspace("na-ws-alpha");
        workspaceB = createWorkspace("na-ws-bravo");
        rawTokenA = "tok_pg_alpha_" + UUID.randomUUID();
        rawTokenB = "tok_pg_bravo_" + UUID.randomUUID();
        tokenA = createToken(workspaceA, "Token A", rawTokenA, Instant.now().plus(1, ChronoUnit.DAYS), false);
        tokenB = createToken(workspaceB, "Token B", rawTokenB, Instant.now().plus(1, ChronoUnit.DAYS), false);
    }

    // ─── Group 1: Password Non-Cleartext Storage, Hashing & Request-Log Redaction ───

    @Test
    // RFC7643-9.2-287493, RFC7643-4.1.1-6515f1, RFC7643-4.1.1-328207, RFC7643-9.2-e4d59c, RFC7644-7.7-f11467
    void group1_passwordsHashedInPostgresAndRedactedInRequestLogsAndAsyncEvents() throws Exception {
        String pwCreate = "PgCleartextCreate!101";
        String pwReplace = "PgCleartextReplace!202";
        String pwPatch = "PgCleartextPatch!303";
        String pwBulkPost = "PgCleartextBulkPost!404";
        String pwBulkPatch = "PgCleartextBulkPatch!505";
        String pwAsync = "PgCleartextAsync!606";
        String pwMalformed = "PgCleartextMalformed!707";
        String pwMalformedPatchPathOpVal = "PgCleartextPatchPathOpVal!808";
        String pwMalformedPatchValOpPath = "PgCleartextPatchValOpPath!909";

        // 1. POST /Users
        MvcResult createRes = mockMvc.perform(post(scimPath(workspaceA, "/Users"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(ScimUserMapper.USER_SCHEMA),
                                "userName", "pg.alice",
                                "password", pwCreate))))
                .andExpect(status().isCreated())
                .andReturn();
        UUID userId = UUID.fromString((String) readJson(createRes).get("id"));
        assertPostgresPasswordBcrypt(userId, pwCreate);

        // 2. PUT /Users/{id}
        mockMvc.perform(put(scimPath(workspaceA, "/Users/" + userId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(ScimUserMapper.USER_SCHEMA),
                                "userName", "pg.alice",
                                "password", pwReplace))))
                .andExpect(status().isOk());
        assertPostgresPasswordBcrypt(userId, pwReplace);

        // 3. PATCH /Users/{id}
        mockMvc.perform(patch(scimPath(workspaceA, "/Users/" + userId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(PATCH_OP_SCHEMA),
                                "Operations", List.of(Map.of(
                                        "op", "replace",
                                        "path", "password",
                                        "value", pwPatch))))))
                .andExpect(status().isOk());
        assertPostgresPasswordBcrypt(userId, pwPatch);

        // 4. POST /Bulk (POST + PATCH with passwords)
        mockMvc.perform(post(scimPath(workspaceA, "/Bulk"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(BULK_REQUEST_SCHEMA),
                                "Operations", List.of(
                                        Map.of(
                                                "method", "POST",
                                                "path", "/Users",
                                                "bulkId", "bUser1",
                                                "data", Map.of("userName", "pg.bulk", "password", pwBulkPost)),
                                        Map.of(
                                                "method", "PATCH",
                                                "path", "/Users/bulkId:bUser1",
                                                "data", Map.of(
                                                        "schemas", List.of(PATCH_OP_SCHEMA),
                                                        "Operations", List.of(Map.of(
                                                                "op", "replace",
                                                                "path", "password",
                                                                "value", pwBulkPatch)))))))))
                .andExpect(status().isOk());
        ScimUser bulkUser = userRepository.findByUserNameIgnoreCaseAndWorkspaceId("pg.bulk", workspaceA.getId())
                .orElseThrow();
        assertPostgresPasswordBcrypt(bulkUser.getId(), pwBulkPatch);

        // 5. Async POST /Users (Prefer: respond-async)
        MvcResult asyncRes = mockMvc.perform(post(scimPath(workspaceA, "/Users"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .header("Prefer", "respond-async")
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(ScimUserMapper.USER_SCHEMA),
                                "userName", "pg.async",
                                "password", pwAsync))))
                .andExpect(status().isAccepted())
                .andReturn();
        String location = asyncRes.getResponse().getHeader("Location");
        assertThat(location).contains("/Events/");
        String txnId = location.substring(location.lastIndexOf('/') + 1);

        // Poll /Events/{txnId} (awaits in-flight completion up to 2s)
        mockMvc.perform(get(scimPath(workspaceA, "/Events/" + txnId))
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isOk());
        ScimUser asyncUser = userRepository.findByUserNameIgnoreCaseAndWorkspaceId("pg.async", workspaceA.getId())
                .orElseThrow();
        assertPostgresPasswordBcrypt(asyncUser.getId(), pwAsync);

        // 6. Malformed/truncated JSON & PATCH (including intervening "op" between "path" and "value" in both orders)
        mockMvc.perform(post(scimPath(workspaceA, "/Users"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content("{\"userName\":\"broken\",\"password\":\"" + pwMalformed + "\""))
                .andExpect(status().isBadRequest());
        mockMvc.perform(patch(scimPath(workspaceA, "/Users/" + userId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content("{\"Operations\":[{\"path\":\"password\",\"op\":\"replace\",\"value\":\"" + pwMalformedPatchPathOpVal))
                .andExpect(status().isBadRequest());
        mockMvc.perform(patch(scimPath(workspaceA, "/Users/" + userId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content("{\"Operations\":[{\"value\":\"" + pwMalformedPatchValOpPath + "\",\"op\":\"replace\",\"path\":\"password\""))
                .andExpect(status().isBadRequest());

        // Inspect PostgreSQL tables directly for zero cleartext password storage
        List<String> allSecrets = List.of(
                pwCreate, pwReplace, pwPatch, pwBulkPost, pwBulkPatch, pwAsync,
                pwMalformed, pwMalformedPatchPathOpVal, pwMalformedPatchValOpPath);

        List<String> dbPasswords = jdbcTemplate.queryForList(
                "SELECT password FROM scim_users WHERE workspace_id = ?",
                String.class,
                workspaceA.getId());
        assertThat(dbPasswords).isNotEmpty();

        List<Map<String, Object>> logRows = jdbcTemplate.queryForList(
                "SELECT request_body, response_body FROM scim_request_logs WHERE workspace_id = ?",
                workspaceA.getId());
        assertThat(logRows).isNotEmpty();

        List<String> eventPayloads = jdbcTemplate.queryForList(
                "SELECT set_payload FROM scim_async_events WHERE workspace_id = ?",
                String.class,
                workspaceA.getId());
        assertThat(eventPayloads).isNotEmpty();

        boolean sawRedacted = false;
        for (Map<String, Object> row : logRows) {
            String reqBody = (String) row.get("request_body");
            String respBody = (String) row.get("response_body");
            if (reqBody != null && reqBody.contains("[REDACTED]")) {
                sawRedacted = true;
            }
            for (String secret : allSecrets) {
                if (reqBody != null) {
                    assertThat(reqBody).doesNotContain(secret);
                }
                if (respBody != null) {
                    assertThat(respBody).doesNotContain(secret);
                }
            }
        }
        assertThat(sawRedacted).isTrue();

        for (String secret : allSecrets) {
            for (String dbPw : dbPasswords) {
                if (dbPw != null) {
                    assertThat(dbPw).doesNotContain(secret);
                }
            }
            for (String payload : eventPayloads) {
                if (payload != null) {
                    assertThat(payload).doesNotContain(secret);
                }
            }
        }
    }

    // ─── Group 2: Immutable Attribute Semantics on PUT & PATCH ───

    @Test
    // RFC7643-7-031493, RFC7644-3.5.1-2e5206, RFC7644-3.5.1-019f75, RFC7644-3.5.2-0cc87d
    void group2_immutableGroupMemberSemanticsOnPutAndPatchInPostgres() throws Exception {
        ScimUser u1 = seedUser(workspaceA, "pg.member.1", "Pass!1");
        ScimUser u2 = seedUser(workspaceA, "pg.member.2", "Pass!2");
        ScimUser u3 = seedUser(workspaceA, "pg.member.3", "Pass!3");

        MvcResult createGroupRes = mockMvc.perform(post(scimPath(workspaceA, "/Groups"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "displayName", "PgImmutableGroup",
                                "members", List.of(Map.of("value", u1.getId().toString(), "type", "User"))))))
                .andExpect(status().isCreated())
                .andReturn();
        UUID groupId = UUID.fromString((String) readJson(createGroupRes).get("id"));

        // PUT with matching value and type succeeds (200)
        mockMvc.perform(put(scimPath(workspaceA, "/Groups/" + groupId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "displayName", "PgImmutableGroup",
                                "members", List.of(Map.of("value", u1.getId().toString(), "type", "User"))))))
                .andExpect(status().isOk());

        // PUT changing existing member type ("User" -> "Group") returns 400 mutability
        mockMvc.perform(put(scimPath(workspaceA, "/Groups/" + groupId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "displayName", "PgImmutableGroup",
                                "members", List.of(Map.of("value", u1.getId().toString(), "type", "Group"))))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("mutability"));

        // PATCH replace / remove on .type, .value, .$ref returns 400 mutability
        for (String op : List.of("replace", "remove")) {
            for (String subAttr : List.of("type", "value", "$ref")) {
                Map<String, Object> patchOp = new LinkedHashMap<>();
                patchOp.put("op", op);
                patchOp.put("path", "members[value eq \"" + u1.getId() + "\"]." + subAttr);
                if ("replace".equals(op)) {
                    patchOp.put("value", "Group");
                }
                mockMvc.perform(patch(scimPath(workspaceA, "/Groups/" + groupId))
                                .header("Authorization", "Bearer " + rawTokenA)
                                .contentType(SCIM_CONTENT_TYPE)
                                .content(objectMapper.writeValueAsString(Map.of(
                                        "schemas", List.of(PATCH_OP_SCHEMA),
                                        "Operations", List.of(patchOp)))))
                        .andExpect(status().isBadRequest())
                        .andExpect(jsonPath("$.scimType").value("mutability"));
            }
        }

        // PATCH add new member succeeds (200)
        mockMvc.perform(patch(scimPath(workspaceA, "/Groups/" + groupId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(PATCH_OP_SCHEMA),
                                "Operations", List.of(Map.of(
                                        "op", "add",
                                        "path", "members",
                                        "value", List.of(
                                                Map.of("value", u2.getId().toString(), "type", "User"),
                                                Map.of("value", u3.getId().toString()))))))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.members.length()").value(3));

        // Clear member_type to '' in PostgreSQL to represent a member whose immutable type was not previously set
        jdbcTemplate.update(
                "UPDATE scim_group_memberships SET member_type = '' WHERE group_id = ? AND member_value = ?",
                groupId, u3.getId());

        // Object-level PATCH replace cannot initialize a previously unset immutable 'type' (only PATCH add may)
        mockMvc.perform(patch(scimPath(workspaceA, "/Groups/" + groupId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(PATCH_OP_SCHEMA),
                                "Operations", List.of(Map.of(
                                        "op", "replace",
                                        "path", "members[value eq \"" + u3.getId() + "\"]",
                                        "value", Map.of("type", "User")))))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("mutability"));

        // PATCH add on previously unset immutable .type succeeds (200)
        mockMvc.perform(patch(scimPath(workspaceA, "/Groups/" + groupId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(PATCH_OP_SCHEMA),
                                "Operations", List.of(Map.of(
                                        "op", "add",
                                        "path", "members[value eq \"" + u3.getId() + "\"].type",
                                        "value", "User"))))))
                .andExpect(status().isOk());

        String persistedType = jdbcTemplate.queryForObject(
                "SELECT member_type FROM scim_group_memberships WHERE group_id = ? AND member_value = ?",
                String.class, groupId, u3.getId());
        assertThat(persistedType).isEqualTo("User");

        // Subsequent PATCH add with conflicting .type ("Group") returns 400 mutability
        mockMvc.perform(patch(scimPath(workspaceA, "/Groups/" + groupId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(PATCH_OP_SCHEMA),
                                "Operations", List.of(Map.of(
                                        "op", "add",
                                        "path", "members[value eq \"" + u3.getId() + "\"].type",
                                        "value", "Group"))))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("mutability"));
    }

    // ─── Group 3: Subject Mapping, Multi-Tenant Isolation & Token Lifetime/Storage ───

    @Test
    // RFC7644-2-fccd30, RFC7644-2-d8fe6f, RFC7644-6.1-26ac86, RFC7644-7.4-66599e, RFC7644-7.4-cb7a78
    void group3_multiWorkspaceIsolationAndTokenLifetimeInPostgres() throws Exception {
        // Verify SHA-256 token hash persisted in PostgreSQL (never raw token)
        String storedHashA = jdbcTemplate.queryForObject(
                "SELECT token_hash FROM workspace_tokens WHERE id = ?",
                String.class, tokenA.getId());
        assertThat(storedHashA)
                .isEqualTo(TokenSecurityUtil.sha256Hex(rawTokenA))
                .isNotEqualTo(rawTokenA)
                .hasSize(64);

        // Create resources in Workspace B
        ScimUser userB = seedUser(workspaceB, "pg.bravo.user", "BravoSecret!1");
        ScimGroup groupB = seedGroup(workspaceB, "PgBravoGroup");
        ScimAsyncEvent eventB = new ScimAsyncEvent();
        eventB.setTxnId(UUID.randomUUID());
        eventB.setWorkspace(workspaceB);
        eventB.setOperation("POST");
        eventB.setResourceType("User");
        eventB.setResourceId(userB.getId());
        eventB.setStatus("PENDING");
        asyncEventRepository.saveAndFlush(eventB);

        // 1. Presenting Token A against Workspace B endpoints is rejected (401)
        mockMvc.perform(get(scimPath(workspaceB, "/Users")).header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get(scimPath(workspaceB, "/Groups")).header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(post(scimPath(workspaceB, "/.search"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of("schemas", List.of(SEARCH_REQUEST_SCHEMA)))))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(post(scimPath(workspaceB, "/Bulk"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of("schemas", List.of(BULK_REQUEST_SCHEMA), "Operations", List.of()))))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get(scimPath(workspaceB, "/Events/" + eventB.getTxnId()))
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isUnauthorized());

        // 2. Workspace B resource IDs are unreachable (404) from Workspace A using Token A
        mockMvc.perform(get(scimPath(workspaceA, "/Users/" + userB.getId())).header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isNotFound());
        mockMvc.perform(put(scimPath(workspaceA, "/Users/" + userB.getId()))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of("userName", "hijacked"))))
                .andExpect(status().isNotFound());
        mockMvc.perform(patch(scimPath(workspaceA, "/Users/" + userB.getId()))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(PATCH_OP_SCHEMA),
                                "Operations", List.of(Map.of("op", "replace", "path", "displayName", "value", "Hijacked"))))))
                .andExpect(status().isNotFound());
        mockMvc.perform(delete(scimPath(workspaceA, "/Users/" + userB.getId())).header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isNotFound());

        mockMvc.perform(get(scimPath(workspaceA, "/Groups/" + groupB.getId())).header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isNotFound());
        mockMvc.perform(put(scimPath(workspaceA, "/Groups/" + groupB.getId()))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of("displayName", "HijackedGroup"))))
                .andExpect(status().isNotFound());
        mockMvc.perform(patch(scimPath(workspaceA, "/Groups/" + groupB.getId()))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(PATCH_OP_SCHEMA),
                                "Operations", List.of(Map.of("op", "replace", "path", "displayName", "value", "HijackedGroup"))))))
                .andExpect(status().isNotFound());
        mockMvc.perform(delete(scimPath(workspaceA, "/Groups/" + groupB.getId())).header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isNotFound());

        mockMvc.perform(get(scimPath(workspaceA, "/Events/" + eventB.getTxnId()))
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isNotFound());

        // 3. Token lifetime & revocation
        String futureRaw = "tok_pg_future_" + UUID.randomUUID();
        createToken(workspaceA, "Future", futureRaw, Instant.now().plus(2, ChronoUnit.HOURS), false);
        mockMvc.perform(get(scimPath(workspaceA, "/Users")).header("Authorization", "Bearer " + futureRaw))
                .andExpect(status().isOk());

        String expiredRaw = "tok_pg_expired_" + UUID.randomUUID();
        createToken(workspaceA, "Expired", expiredRaw, Instant.now().minus(5, ChronoUnit.MINUTES), false);
        mockMvc.perform(get(scimPath(workspaceA, "/Users")).header("Authorization", "Bearer " + expiredRaw))
                .andExpect(status().isUnauthorized());

        String revokedRaw = "tok_pg_revoked_" + UUID.randomUUID();
        createToken(workspaceA, "Revoked", revokedRaw, Instant.now().plus(2, ChronoUnit.HOURS), true);
        mockMvc.perform(get(scimPath(workspaceA, "/Users")).header("Authorization", "Bearer " + revokedRaw))
                .andExpect(status().isUnauthorized());
    }

    // ─── Group 4: Cursor Pagination Security ───

    @Test
    // RFC9865-5.2-230645
    void group4_cursorConfinementAcrossWorkspacesInPostgres() throws Exception {
        seedUser(workspaceA, "pg.alpha.1", "Alpha!1");
        seedUser(workspaceA, "pg.alpha.2", "Alpha!2");
        seedUser(workspaceA, "pg.alpha.3", "Alpha!3");
        seedUser(workspaceB, "pg.bravo.only", "Bravo!1");

        MvcResult page1A = mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("cursor", "")
                        .param("count", "1")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isOk())
                .andReturn();
        String cursorA = (String) readJson(page1A).get("nextCursor");
        assertThat(cursorA).isNotBlank();

        MvcResult crossRes = mockMvc.perform(get(scimPath(workspaceB, "/Users"))
                        .param("cursor", cursorA)
                        .param("count", "1")
                        .header("Authorization", "Bearer " + rawTokenB))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("invalidCursor"))
                .andReturn();
        assertThat(crossRes.getResponse().getContentAsString())
                .doesNotContain("pg.alpha.1")
                .doesNotContain("pg.alpha.2")
                .doesNotContain("pg.alpha.3");

        mockMvc.perform(get(scimPath(workspaceB, "/Users"))
                        .param("cursor", "")
                        .param("count", "10")
                        .header("Authorization", "Bearer " + rawTokenB))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalResults").value(1))
                .andExpect(jsonPath("$.Resources[0].userName").value("pg.bravo.only"));
    }

    @Test
    // RFC9865-5.2-535e56
    void group4_cursorDeniedImmediatelyAfterPostgresTokenRevocation() throws Exception {
        seedUser(workspaceA, "pg.rev.1", "Secret!1");
        seedUser(workspaceA, "pg.rev.2", "Secret!2");

        MvcResult page1 = mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("cursor", "")
                        .param("count", "1")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isOk())
                .andReturn();
        String nextCursor = (String) readJson(page1).get("nextCursor");
        assertThat(nextCursor).isNotBlank();

        // Update revoked = true directly in PostgreSQL
        jdbcTemplate.update("UPDATE workspace_tokens SET revoked = true WHERE id = ?", tokenA.getId());

        MvcResult page2 = mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("cursor", nextCursor)
                        .param("count", "1")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isUnauthorized())
                .andReturn();
        assertThat(readJson(page2)).doesNotContainKey("Resources");
    }

    @Test
    // RFC9865-5.2-535e56
    void group4_cursorDeniedImmediatelyAfterPostgresTokenExpiry() throws Exception {
        seedUser(workspaceA, "pg.exp.1", "Secret!1");
        seedUser(workspaceA, "pg.exp.2", "Secret!2");

        MvcResult page1 = mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("cursor", "")
                        .param("count", "1")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isOk())
                .andReturn();
        String nextCursor = (String) readJson(page1).get("nextCursor");
        assertThat(nextCursor).isNotBlank();

        // Update expires_at = past directly in PostgreSQL
        jdbcTemplate.update(
                "UPDATE workspace_tokens SET expires_at = ? WHERE id = ?",
                Timestamp.from(Instant.now().minus(5, ChronoUnit.MINUTES)),
                tokenA.getId());

        MvcResult page2 = mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("cursor", nextCursor)
                        .param("count", "1")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isUnauthorized())
                .andReturn();
        assertThat(readJson(page2)).doesNotContainKey("Resources");
    }

    @Test
    // RFC9865-5.2-826018
    void group4_cursorErrorScenariosExposeZeroSensitiveDataInPostgres() throws Exception {
        String seededPassword = "PgUltraConfidentialPassword!999";
        ScimUser seededUser = seedUser(workspaceA, "pg.confidential.alpha", seededPassword);

        String validCursorA = ScimCursorCodec.encodeCursor(workspaceA.getId(), 1);
        String truncatedCursor = validCursorA.substring(0, ScimCursorCodec.CURSOR_PREFIX.length() + 6);
        String invalidBase64Cursor = ScimCursorCodec.CURSOR_PREFIX + "%%%not_base64%%%";
        String malformedJsonCursor = ScimCursorTestHelper.encodeSignedRawJson("{malformed_json");
        String tamperedJsonCursor = tamperCursorPayload(validCursorA);
        String expiredCursor = ScimCursorTestHelper.encodeExpiredCursor(workspaceA.getId(), 1);

        List<String> whiteBoxSecrets = List.of(
                rawTokenA,
                rawTokenB,
                tokenA.getTokenHash(),
                tokenB.getTokenHash(),
                workspaceA.getId().toString(),
                workspaceB.getId().toString(),
                DB_PASSWORD_SECRET,
                seededUser.getId().toString(),
                seededUser.getUserName(),
                seededPassword
        );
        List<String> stackAndSqlMarkers = List.of(
                "goroutine", "panic", "Exception", "select ", "insert ", ".go:", ".java:"
        );

        List<MvcResult> errorResponses = new ArrayList<>();
        for (String badCursor : List.of(
                truncatedCursor, invalidBase64Cursor, malformedJsonCursor, tamperedJsonCursor, expiredCursor)) {
            errorResponses.add(mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                            .param("cursor", badCursor)
                            .param("count", "1")
                            .header("Authorization", "Bearer " + rawTokenA))
                    .andExpect(status().isBadRequest())
                    .andReturn());
        }
        errorResponses.add(mockMvc.perform(get(scimPath(workspaceB, "/Users"))
                        .param("cursor", validCursorA)
                        .param("count", "1")
                        .header("Authorization", "Bearer " + rawTokenB))
                .andExpect(status().isBadRequest())
                .andReturn());
        errorResponses.add(mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("cursor", "")
                        .param("startIndex", "1")
                        .param("count", "-5")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isBadRequest())
                .andReturn());
        errorResponses.add(mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("cursor", "")
                        .param("count", "invalidInt")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isBadRequest())
                .andReturn());
        errorResponses.add(mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("cursor", "")
                        .param("count", "201")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isBadRequest())
                .andReturn());

        for (MvcResult res : errorResponses) {
            String bodyStr = res.getResponse().getContentAsString();
            Map<String, Object> parsed = readJson(res);
            assertThat(parsed.get("schemas")).isEqualTo(List.of(ERROR_SCHEMA));
            for (String secret : whiteBoxSecrets) {
                assertThat(bodyStr).doesNotContain(secret);
            }
            for (String marker : stackAndSqlMarkers) {
                assertThat(bodyStr).doesNotContain(marker);
            }
        }
    }

    // ─── Group 5: Result Size Cap, Sanitized 500 Errors & Version-Agnostic $ref ───

    @Test
    // RFC7644-3.4.2.1-145a1a, RFC7644-3.12-40cb84
    void group5_maxResultsClampedOnIndexAndTooManyOnCursorInPostgres() throws Exception {
        List<ScimUser> batch = new ArrayList<>(205);
        for (int i = 0; i < 205; i++) {
            ScimUser u = new ScimUser();
            u.setWorkspace(workspaceA);
            u.setUserName("pg.cap." + i);
            batch.add(u);
        }
        userRepository.saveAllAndFlush(batch);

        mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("count", "500")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalResults").value(205))
                .andExpect(jsonPath("$.itemsPerPage").value(200))
                .andExpect(jsonPath("$.Resources.length()").value(200));

        mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("cursor", "")
                        .param("count", "201")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("tooMany"));

        mockMvc.perform(get(scimPath(workspaceA, "/Groups"))
                        .param("cursor", "")
                        .param("count", "201")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("tooMany"));

        mockMvc.perform(post(scimPath(workspaceA, "/.search"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(SEARCH_REQUEST_SCHEMA),
                                "cursor", "",
                                "count", 201))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("tooMany"));
    }

    @Test
    // RFC7644-3.12-991537
    void group5_internal500ErrorSanitizedWithoutSqlOrExceptionLeakInPostgres() throws Exception {
        // 1. Live HTTP 500 path via failed non-SET ScimAsyncEvent containing raw SQL/JDBC text
        ScimAsyncEvent failedEvent = new ScimAsyncEvent();
        failedEvent.setTxnId(UUID.randomUUID());
        failedEvent.setWorkspace(workspaceA);
        failedEvent.setOperation("POST");
        failedEvent.setResourceType("User");
        failedEvent.setStatus("FAILED");
        failedEvent.setCompletedAt(Instant.now().truncatedTo(ChronoUnit.MICROS));
        failedEvent.setSetPayload(
                "SQLException: select password from scim_users; jdbc:postgresql://scim-db:5432/scimplayground; user=" + DB_PASSWORD_SECRET);
        asyncEventRepository.saveAndFlush(failedEvent);

        MvcResult http500 = mockMvc.perform(get(scimPath(workspaceA, "/Events/" + failedEvent.getTxnId()))
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.schemas[0]").value(ERROR_SCHEMA))
                .andExpect(jsonPath("$.status").value("500"))
                .andExpect(jsonPath("$.detail").value("Internal server error"))
                .andReturn();

        String bodyStr = http500.getResponse().getContentAsString();
        assertThat(bodyStr)
                .doesNotContain("SQLException")
                .doesNotContain("select ")
                .doesNotContain("jdbc:postgresql")
                .doesNotContain(DB_PASSWORD_SECRET);

        // 2. Spring-wired ScimExceptionHandler transaction failure path
        TransactionSystemException txEx = new TransactionSystemException(
                "Could not commit JPA transaction",
                new SQLException("ERROR: insert into scim_users failed; password=" + DB_PASSWORD_SECRET));
        ResponseEntity<Map<String, Object>> txResp = exceptionHandler.handleTransactionSystemException(txEx);
        assertThat(txResp.getStatusCode().value()).isEqualTo(500);
        assertThat(txResp.getBody()).isNotNull();
        assertThat(txResp.getBody().get("detail")).isEqualTo("Internal server error");
        assertThat(txResp.getBody().toString())
                .doesNotContain("insert ")
                .doesNotContain("scim_users")
                .doesNotContain(DB_PASSWORD_SECRET);
    }

    @Test
    // RFC7643-2.4-63934b
    void group5_versionAgnosticRefAcceptedNormalizedAndFilteredInPostgres() throws Exception {
        ScimUser mgr1 = seedUser(workspaceA, "pg.manager.one", "Pass!1");
        ScimUser mgr2 = seedUser(workspaceA, "pg.manager.two", "Pass!2");
        ScimUser extraMember = seedUser(workspaceA, "pg.member.extra", "Pass!3");

        // 1. $ref-only enterprise.manager on POST, PUT, and PATCH (without "value")
        MvcResult empRes = mockMvc.perform(post(scimPath(workspaceA, "/Users"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(ScimUserMapper.USER_SCHEMA, ScimUserMapper.ENTERPRISE_SCHEMA),
                                "userName", "pg.employee.ref",
                                ScimUserMapper.ENTERPRISE_SCHEMA, Map.of(
                                        "manager", Map.of(
                                                "$ref", "https://legacy.example.com/scim/v1/Users/" + mgr1.getId().toString().toUpperCase()))))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$['" + ScimUserMapper.ENTERPRISE_SCHEMA + "'].manager.value").value(mgr1.getId().toString()))
                .andReturn();
        Map<String, Object> empJson = readJson(empRes);
        UUID empId = UUID.fromString((String) empJson.get("id"));
        @SuppressWarnings("unchecked")
        Map<String, Object> entOut = (Map<String, Object>) empJson.get(ScimUserMapper.ENTERPRISE_SCHEMA);
        @SuppressWarnings("unchecked")
        Map<String, Object> mgrOut = (Map<String, Object>) entOut.get("manager");
        assertThat((String) mgrOut.get("$ref")).endsWith("/ws/" + workspaceA.getId() + "/scim/v2/Users/" + mgr1.getId());

        // PUT with $ref-only relative ../Users/<mgr2>
        mockMvc.perform(put(scimPath(workspaceA, "/Users/" + empId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(ScimUserMapper.USER_SCHEMA, ScimUserMapper.ENTERPRISE_SCHEMA),
                                "userName", "pg.employee.ref",
                                ScimUserMapper.ENTERPRISE_SCHEMA, Map.of(
                                        "manager", Map.of("$ref", "../Users/" + mgr2.getId()))))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$['" + ScimUserMapper.ENTERPRISE_SCHEMA + "'].manager.value").value(mgr2.getId().toString()));

        // PATCH with $ref-only relative /Users/<mgr1> (persists enterprise_manager_ref = "/Users/<mgr1>" in PostgreSQL)
        mockMvc.perform(patch(scimPath(workspaceA, "/Users/" + empId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(PATCH_OP_SCHEMA),
                                "Operations", List.of(Map.of(
                                        "op", "replace",
                                        "path", ScimUserMapper.ENTERPRISE_SCHEMA + ":manager",
                                        "value", Map.of("$ref", "/Users/" + mgr1.getId())))))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$['" + ScimUserMapper.ENTERPRISE_SCHEMA + "'].manager.value").value(mgr1.getId().toString()));

        // 2. Cross-version $ref-only Group.members deduplication on POST, plus PUT, PATCH add, PATCH remove, and Bulk $ref
        MvcResult grpRes = mockMvc.perform(post(scimPath(workspaceA, "/Groups"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "displayName", "PgVersionAgnosticGroup",
                                "members", List.of(
                                        Map.of("$ref", "https://old.example.com/scim/v1/Users/" + empId),
                                        Map.of("$ref", "/Users/" + empId))))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.members.length()").value(1))
                .andExpect(jsonPath("$.members[0].value").value(empId.toString()))
                .andReturn();
        Map<String, Object> grpJson = readJson(grpRes);
        String grpId = (String) grpJson.get("id");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> membersOut = (List<Map<String, Object>>) grpJson.get("members");
        assertThat((String) membersOut.get(0).get("$ref")).endsWith("/ws/" + workspaceA.getId() + "/scim/v2/Users/" + empId);

        mockMvc.perform(patch(scimPath(workspaceA, "/Groups/" + grpId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(PATCH_OP_SCHEMA),
                                "Operations", List.of(Map.of(
                                        "op", "add",
                                        "path", "members",
                                        "value", List.of(Map.of("$ref", "../Users/" + extraMember.getId()))))))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.members.length()").value(2));

        mockMvc.perform(patch(scimPath(workspaceA, "/Groups/" + grpId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(PATCH_OP_SCHEMA),
                                "Operations", List.of(Map.of(
                                        "op", "remove",
                                        "path", "members",
                                        "value", List.of(Map.of("$ref", "https://legacy.example/scim/v1/Users/" + extraMember.getId()))))))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.members.length()").value(1))
                .andExpect(jsonPath("$.members[0].value").value(empId.toString()));

        mockMvc.perform(put(scimPath(workspaceA, "/Groups/" + grpId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "displayName", "PgVersionAgnosticGroup",
                                "members", List.of(Map.of("$ref", "https://idp.example.com/scim/v1/Users/" + empId))))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.members.length()").value(1))
                .andExpect(jsonPath("$.members[0].value").value(empId.toString()));

        mockMvc.perform(post(scimPath(workspaceA, "/Bulk"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(BULK_REQUEST_SCHEMA),
                                "Operations", List.of(
                                        Map.of("method", "POST", "path", "/Users", "bulkId", "pgRefBulkUser",
                                                "data", Map.of("userName", "pg.bulk.ref.only")),
                                        Map.of("method", "POST", "path", "/Groups", "bulkId", "pgRefBulkGroup",
                                                "data", Map.of(
                                                        "displayName", "PgBulkRefOnlyGroup",
                                                        "members", List.of(Map.of("$ref", "/Users/bulkId:pgRefBulkUser")))))))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.Operations[0].status").value("201"))
                .andExpect(jsonPath("$.Operations[1].status").value("201"));

        // 3. Conflict & invalid $ref rejection (400 invalidValue) on both Group.members and enterprise.manager across POST, PUT, PATCH
        mockMvc.perform(post(scimPath(workspaceA, "/Groups"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "displayName", "PgConflictGroupPost",
                                "members", List.of(Map.of(
                                        "value", empId.toString(),
                                        "$ref", "https://idp.example.com/scim/v2/Users/" + mgr1.getId()))))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("invalidValue"));

        mockMvc.perform(put(scimPath(workspaceA, "/Groups/" + grpId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "displayName", "PgVersionAgnosticGroup",
                                "members", List.of(Map.of(
                                        "value", empId.toString(),
                                        "$ref", "https://example.com/OtherPath/123"))))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("invalidValue"));

        mockMvc.perform(patch(scimPath(workspaceA, "/Groups/" + grpId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(PATCH_OP_SCHEMA),
                                "Operations", List.of(Map.of(
                                        "op", "add",
                                        "path", "members",
                                        "value", List.of(Map.of(
                                                "value", empId.toString(),
                                                "$ref", "/Users/" + mgr1.getId()))))))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("invalidValue"));

        mockMvc.perform(post(scimPath(workspaceA, "/Users"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(ScimUserMapper.USER_SCHEMA, ScimUserMapper.ENTERPRISE_SCHEMA),
                                "userName", "pg.bad.mgr.post",
                                ScimUserMapper.ENTERPRISE_SCHEMA, Map.of(
                                        "manager", Map.of("value", mgr1.getId().toString(), "$ref", "/Users/" + mgr2.getId()))))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("invalidValue"));

        mockMvc.perform(put(scimPath(workspaceA, "/Users/" + empId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(ScimUserMapper.USER_SCHEMA, ScimUserMapper.ENTERPRISE_SCHEMA),
                                "userName", "pg.employee.ref",
                                ScimUserMapper.ENTERPRISE_SCHEMA, Map.of(
                                        "manager", Map.of("$ref", "https://example.com/OtherPath/123"))))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("invalidValue"));

        mockMvc.perform(patch(scimPath(workspaceA, "/Users/" + empId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(PATCH_OP_SCHEMA),
                                "Operations", List.of(Map.of(
                                        "op", "replace",
                                        "path", ScimUserMapper.ENTERPRISE_SCHEMA + ":manager.$ref",
                                        "value", "/Groups/" + mgr1.getId()))))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("invalidValue"));

        // 4. Live PostgreSQL JPA/SQL + valuePath $ref filtering across manager.$ref, members.$ref, and groups.$ref
        // Even though emp was persisted with relative "/Users/<mgr1>", full v2, v1, and ../Users/<mgr1> all match in SQL!
        for (String filterRef : List.of(
                "/Users/" + mgr1.getId(),
                "../Users/" + mgr1.getId(),
                "https://legacy.example/scim/v1/Users/" + mgr1.getId(),
                "https://modern.example/ws/" + workspaceA.getId() + "/scim/v2/Users/" + mgr1.getId())) {
            mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                            .param("filter", ScimUserMapper.ENTERPRISE_SCHEMA + ":manager.$ref eq \"" + filterRef + "\"")
                            .header("Authorization", "Bearer " + rawTokenA))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.totalResults").value(1))
                    .andExpect(jsonPath("$.Resources[0].userName").value("pg.employee.ref"));
        }

        // Verify SQL 'ne' on manager.$ref excludes pg.employee.ref while matching users without that manager (including NULL manager)
        MvcResult neRes = mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("filter", ScimUserMapper.ENTERPRISE_SCHEMA + ":manager.$ref ne \"https://modern.example/scim/v2/Users/" + mgr1.getId() + "\"")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isOk())
                .andReturn();
        assertThat(neRes.getResponse().getContentAsString())
                .doesNotContain("pg.employee.ref")
                .contains("pg.manager.one");

        for (String groupFilterRef : List.of(
                "/Groups/" + grpId,
                "../Groups/" + grpId,
                "https://legacy.example/scim/v1/Groups/" + grpId,
                "https://modern.example/scim/v2/Groups/" + grpId)) {
            mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                            .param("filter", "groups.$ref eq \"" + groupFilterRef + "\"")
                            .header("Authorization", "Bearer " + rawTokenA))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.totalResults").value(1))
                    .andExpect(jsonPath("$.Resources[0].id").value(empId.toString()));
        }

        for (String memberFilterRef : List.of(
                "/Users/" + empId,
                "../Users/" + empId,
                "https://idp.example.com/scim/v1/Users/" + empId,
                "https://idp.example.com/scim/v2/Users/" + empId)) {
            mockMvc.perform(get(scimPath(workspaceA, "/Groups"))
                            .param("filter", "members.$ref eq \"" + memberFilterRef + "\"")
                            .header("Authorization", "Bearer " + rawTokenA))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.totalResults").value(1))
                    .andExpect(jsonPath("$.Resources[0].id").value(grpId));
        }

        mockMvc.perform(get(scimPath(workspaceA, "/Groups"))
                        .param("filter", "members[$ref eq \"/Users/" + empId + "\"]")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalResults").value(1))
                .andExpect(jsonPath("$.Resources[0].id").value(grpId));
    }

    // ─── Helpers ───

    private Workspace createWorkspace(String prefix) {
        Workspace ws = new Workspace();
        ws.setName(prefix + "-" + UUID.randomUUID());
        ws.setCreatedByUsername("na-compliance@example.com");
        return workspaceRepository.saveAndFlush(ws);
    }

    private WorkspaceToken createToken(Workspace ws, String name, String rawToken, Instant expiresAt, boolean revoked) {
        WorkspaceToken tok = new WorkspaceToken();
        tok.setWorkspace(ws);
        tok.setName(name);
        tok.setTokenHash(TokenSecurityUtil.sha256Hex(rawToken));
        tok.setExpiresAt(expiresAt);
        tok.setRevoked(revoked);
        return tokenRepository.saveAndFlush(tok);
    }

    private ScimUser seedUser(Workspace ws, String userName, String rawPassword) {
        ScimUser u = new ScimUser();
        u.setWorkspace(ws);
        ScimUserMapper.applyFromScimInput(u, Map.of("userName", userName, "password", rawPassword));
        return userRepository.saveAndFlush(u);
    }

    private ScimGroup seedGroup(Workspace ws, String displayName) {
        ScimGroup g = new ScimGroup();
        g.setWorkspace(ws);
        g.setDisplayName(displayName);
        return groupRepository.saveAndFlush(g);
    }

    private void assertPostgresPasswordBcrypt(UUID userId, String expectedRawPassword) {
        String dbHash = jdbcTemplate.queryForObject(
                "SELECT password FROM scim_users WHERE id = ?",
                String.class, userId);
        assertThat(dbHash).isNotNull();
        assertThat(dbHash.startsWith("$2a$") || dbHash.startsWith("$2b$")).isTrue();
        assertThat(dbHash).doesNotContain(expectedRawPassword);
        assertThat(passwordEncoder.matches(expectedRawPassword, dbHash)).isTrue();
    }

    private static String scimPath(Workspace ws, String suffix) {
        return "/ws/" + ws.getId() + "/scim/v2" + suffix;
    }

    private static String tamperCursorPayload(String cursor) {
        String b64 = cursor.substring(ScimCursorCodec.CURSOR_PREFIX.length());
        byte[] decoded = Base64.getUrlDecoder().decode(b64);
        decoded[decoded.length - 2] ^= 0x01;
        return ScimCursorCodec.CURSOR_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(decoded);
    }

    private Map<String, Object> readJson(MvcResult res) throws Exception {
        return objectMapper.readValue(
                res.getResponse().getContentAsString(),
                new TypeReference<Map<String, Object>>() {});
    }
}
