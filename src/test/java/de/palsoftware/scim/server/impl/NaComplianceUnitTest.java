package de.palsoftware.scim.server.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.controller.ScimAsyncEventController;
import de.palsoftware.scim.server.impl.controller.ScimBulkController;
import de.palsoftware.scim.server.impl.controller.ScimDiscoveryController;
import de.palsoftware.scim.server.impl.controller.ScimGroupController;
import de.palsoftware.scim.server.impl.controller.ScimUserController;
import de.palsoftware.scim.server.impl.entity.ScimAsyncEvent;
import de.palsoftware.scim.server.impl.filter.PayloadSizeLimitFilter;
import de.palsoftware.scim.server.impl.logging.RequestResponseLoggingFilter;
import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.model.ScimGroupMembership;
import de.palsoftware.scim.server.impl.model.ScimRequestLog;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.model.WorkspaceToken;
import de.palsoftware.scim.server.impl.repository.ScimAsyncEventRepository;
import de.palsoftware.scim.server.impl.repository.ScimGroupMembershipRepository;
import de.palsoftware.scim.server.impl.repository.ScimGroupRepository;
import de.palsoftware.scim.server.impl.repository.ScimRequestLogRepository;
import de.palsoftware.scim.server.impl.repository.ScimUserRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceTokenRepository;
import de.palsoftware.scim.server.impl.scim.error.ScimExceptionHandler;
import de.palsoftware.scim.server.impl.scim.filter.ScimFilterEvaluator;
import de.palsoftware.scim.server.impl.scim.filter.ScimFilterParser;
import de.palsoftware.scim.server.impl.scim.mapper.ScimUserMapper;
import de.palsoftware.scim.server.impl.scim.pagination.ScimCursorCodec;
import de.palsoftware.scim.server.impl.scim.pagination.ScimCursorTestHelper;
import de.palsoftware.scim.server.impl.security.BearerTokenAuthFilter;
import de.palsoftware.scim.server.impl.security.TokenSecurityUtil;
import de.palsoftware.scim.server.impl.service.ScimAsyncEventService;
import de.palsoftware.scim.server.impl.service.ScimGroupService;
import de.palsoftware.scim.server.impl.service.ScimUserService;
import de.palsoftware.scim.server.impl.service.WorkspaceActivityService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.TransactionSystemException;

import java.sql.SQLException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Full-stack white-box MockMvc compliance tests covering server-applicable {@code na} RFC requirements
 * across RFC 7643, RFC 7644, RFC 9865, and RFC 9967 inside Standard Sandbox (without Docker).
 */
class NaComplianceUnitTest {

    private static final String SCIM_CONTENT_TYPE = "application/scim+json";
    private static final String PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
    private static final String BULK_REQUEST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
    private static final String SEARCH_REQUEST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:SearchRequest";
    private static final String ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
    private static final String SIMULATED_DB_SECRET = "scim_playground_db_secret_991";

    private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private final Map<UUID, Workspace> workspaces = new ConcurrentHashMap<>();
    private final Map<UUID, WorkspaceToken> tokens = new ConcurrentHashMap<>();
    private final Map<UUID, ScimUser> users = new ConcurrentHashMap<>();
    private final Map<UUID, ScimGroup> groups = new ConcurrentHashMap<>();
    private final List<ScimRequestLog> requestLogs = new CopyOnWriteArrayList<>();
    private final Map<UUID, ScimAsyncEvent> asyncEvents = new ConcurrentHashMap<>();
    private final AtomicBoolean failNextUserSaveWithTxError = new AtomicBoolean(false);

    private WorkspaceRepository workspaceRepository;
    private WorkspaceTokenRepository tokenRepository;
    private ScimUserRepository userRepository;
    private ScimGroupRepository groupRepository;
    private ScimGroupMembershipRepository membershipRepository;
    private ScimRequestLogRepository requestLogRepository;
    private ScimAsyncEventRepository asyncEventRepository;

    private MockMvc mockMvc;

    private Workspace workspaceA;
    private Workspace workspaceB;
    private String rawTokenA;
    private String rawTokenB;
    private WorkspaceToken tokenA;
    private WorkspaceToken tokenB;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        workspaces.clear();
        tokens.clear();
        users.clear();
        groups.clear();
        requestLogs.clear();
        asyncEvents.clear();
        failNextUserSaveWithTxError.set(false);

        workspaceRepository = mock(WorkspaceRepository.class);
        tokenRepository = mock(WorkspaceTokenRepository.class);
        userRepository = mock(ScimUserRepository.class);
        groupRepository = mock(ScimGroupRepository.class);
        membershipRepository = mock(ScimGroupMembershipRepository.class);
        requestLogRepository = mock(ScimRequestLogRepository.class);
        asyncEventRepository = mock(ScimAsyncEventRepository.class);
        WorkspaceActivityService activityService = mock(WorkspaceActivityService.class);

        wireInMemoryRepositories();

        ScimUserService userService = new ScimUserService(
                userRepository, membershipRepository, workspaceRepository, activityService) {
            @Override
            public Map<String, Object> listUsers(UUID workspaceId, String filter, String sortBy,
                                                 String sortOrder, int startIndex, int count) {
                ScimFilterParser.FilterNode ast = (filter != null && !filter.isBlank())
                        ? ScimFilterParser.parseAst(filter, true)
                        : null;
                String sortAttr = ScimFilterParser.resolveUserSortAttribute(sortBy);
                boolean isDescending = "descending".equalsIgnoreCase(sortOrder);

                List<ScimUser> wsUsers = users.values().stream()
                        .filter(u -> u.getWorkspace() != null && workspaceId.equals(u.getWorkspace().getId()))
                        .toList();
                List<UUID> ids = wsUsers.stream().map(ScimUser::getId).filter(Objects::nonNull).toList();
                Map<UUID, List<Map<String, Object>>> groupsMap = getUserGroupsBatch(workspaceId, ids, "");

                List<ScimUser> matched = new ArrayList<>();
                for (ScimUser u : wsUsers) {
                    List<Map<String, Object>> ug = groupsMap.getOrDefault(u.getId(), Collections.emptyList());
                    if (ast == null || ScimFilterEvaluator.matchesUser(u, ug, ast)) {
                        matched.add(u);
                    }
                }
                Comparator<ScimUser> cmp = buildUserInMemoryComparator(sortAttr, isDescending);
                matched.sort(cmp);

                long total = matched.size();
                int offset = Math.max(0, startIndex - 1);
                List<ScimUser> page = (count <= 0 || offset >= matched.size())
                        ? Collections.emptyList()
                        : matched.subList(offset, Math.min(matched.size(), offset + count));

                Map<String, Object> res = new LinkedHashMap<>();
                res.put("totalResults", total);
                res.put("startIndex", startIndex);
                res.put("itemsPerPage", page.size());
                res.put("Resources", page);
                return res;
            }
        };

        ScimGroupService groupService = new ScimGroupService(
                groupRepository, membershipRepository, userRepository, workspaceRepository, activityService) {
            @Override
            public Map<String, Object> listGroups(UUID workspaceId, String filter, String sortBy,
                                                  String sortOrder, int startIndex, int count) {
                ScimFilterParser.FilterNode ast = (filter != null && !filter.isBlank())
                        ? ScimFilterParser.parseAst(filter, false)
                        : null;
                String sortAttr = ScimFilterParser.resolveGroupSortAttribute(sortBy);
                boolean isDescending = "descending".equalsIgnoreCase(sortOrder);

                List<ScimGroup> matched = groups.values().stream()
                        .filter(g -> g.getWorkspace() != null && workspaceId.equals(g.getWorkspace().getId()))
                        .filter(g -> ast == null || ScimFilterEvaluator.matchesGroup(g, ast))
                        .sorted(buildGroupInMemoryComparator(sortAttr, isDescending))
                        .toList();

                long total = matched.size();
                int offset = Math.max(0, startIndex - 1);
                List<ScimGroup> page = (count <= 0 || offset >= matched.size())
                        ? Collections.emptyList()
                        : matched.subList(offset, Math.min(matched.size(), offset + count));

                Map<String, Object> res = new LinkedHashMap<>();
                res.put("totalResults", total);
                res.put("startIndex", startIndex);
                res.put("itemsPerPage", page.size());
                res.put("Resources", page);
                return res;
            }
        };

        ScimAsyncEventService asyncEventService = new ScimAsyncEventService(
                asyncEventRepository,
                workspaceRepository,
                objectMapper,
                Runnable::run,
                org.springframework.transaction.support.TransactionOperations.withoutTransaction());

        ScimUserController userController = new ScimUserController(userService, asyncEventService);
        ScimGroupController groupController = new ScimGroupController(groupService, asyncEventService);
        ScimBulkController bulkController = new ScimBulkController(userService, groupService);
        ScimDiscoveryController discoveryController = new ScimDiscoveryController(userService, groupService);
        ScimAsyncEventController asyncEventController = new ScimAsyncEventController(
                asyncEventRepository, objectMapper, asyncEventService);

        BearerTokenAuthFilter authFilter = new BearerTokenAuthFilter(tokenRepository, workspaceRepository, objectMapper);
        PayloadSizeLimitFilter payloadSizeLimitFilter = new PayloadSizeLimitFilter(objectMapper);
        RequestResponseLoggingFilter loggingFilter = new RequestResponseLoggingFilter(
                requestLogRepository, workspaceRepository);

        mockMvc = MockMvcBuilders.standaloneSetup(
                        userController, groupController, bulkController, discoveryController, asyncEventController)
                .setControllerAdvice(new ScimExceptionHandler())
                .addFilters(authFilter, payloadSizeLimitFilter, loggingFilter)
                .build();

        workspaceA = seedWorkspace("tenant-alpha");
        workspaceB = seedWorkspace("tenant-bravo");
        rawTokenA = "tok_alpha_" + UUID.randomUUID();
        rawTokenB = "tok_bravo_" + UUID.randomUUID();
        tokenA = seedToken(workspaceA, "Token A", rawTokenA, Instant.now().plus(1, ChronoUnit.DAYS), false);
        tokenB = seedToken(workspaceB, "Token B", rawTokenB, Instant.now().plus(1, ChronoUnit.DAYS), false);
    }

    // ─── Group 1: Password Non-Cleartext Storage, Hashing & Log Redaction ───

    @Test
    // RFC7643-9.2-287493, RFC7643-4.1.1-6515f1, RFC7643-4.1.1-328207, RFC7643-9.2-e4d59c, RFC7644-7.7-f11467
    void group1_passwordsHashedAtRestAndRedactedAcrossUsersBulkAndAsyncLogs() throws Exception {
        String pwCreate = "CleartextCreate!101";
        String pwReplace = "CleartextReplace!202";
        String pwPatch = "CleartextPatch!303";
        String pwBulkPost = "CleartextBulkPost!404";
        String pwBulkPatch = "CleartextBulkPatch!505";
        String pwAsync = "CleartextAsync!606";
        String pwMalformedPathOpVal = "CleartextMalformedPathOpVal!707";
        String pwMalformedValOpPath = "CleartextMalformedValOpPath!808";

        // 1. POST /Users
        MvcResult createRes = mockMvc.perform(post(scimPath(workspaceA, "/Users"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(ScimUserMapper.USER_SCHEMA),
                                "userName", "alice.sec",
                                "password", pwCreate))))
                .andExpect(status().isCreated())
                .andReturn();
        Map<String, Object> createdMap = readJson(createRes);
        UUID userId = UUID.fromString((String) createdMap.get("id"));
        assertBcryptMatch(users.get(userId), pwCreate);

        // 2. PUT /Users/{id}
        mockMvc.perform(put(scimPath(workspaceA, "/Users/" + userId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(ScimUserMapper.USER_SCHEMA),
                                "userName", "alice.sec",
                                "password", pwReplace))))
                .andExpect(status().isOk());
        assertBcryptMatch(users.get(userId), pwReplace);

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
        assertBcryptMatch(users.get(userId), pwPatch);

        // 4. POST /Bulk (POST + PATCH with passwords)
        MvcResult bulkRes = mockMvc.perform(post(scimPath(workspaceA, "/Bulk"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(BULK_REQUEST_SCHEMA),
                                "Operations", List.of(
                                        Map.of(
                                                "method", "POST",
                                                "path", "/Users",
                                                "bulkId", "u1",
                                                "data", Map.of("userName", "bulk.sec", "password", pwBulkPost)),
                                        Map.of(
                                                "method", "PATCH",
                                                "path", "/Users/bulkId:u1",
                                                "data", Map.of(
                                                        "schemas", List.of(PATCH_OP_SCHEMA),
                                                        "Operations", List.of(Map.of(
                                                                "op", "replace",
                                                                "path", "password",
                                                                "value", pwBulkPatch)))))))))
                .andExpect(status().isOk())
                .andReturn();
        ScimUser bulkUser = users.values().stream()
                .filter(u -> "bulk.sec".equals(u.getUserName()))
                .findFirst()
                .orElseThrow();
        assertBcryptMatch(bulkUser, pwBulkPatch);

        // 5. Async POST /Users (Prefer: respond-async)
        MvcResult asyncRes = mockMvc.perform(post(scimPath(workspaceA, "/Users"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .header("Prefer", "respond-async")
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(ScimUserMapper.USER_SCHEMA),
                                "userName", "async.sec",
                                "password", pwAsync))))
                .andExpect(status().isAccepted())
                .andReturn();
        String location = asyncRes.getResponse().getHeader("Location");
        assertThat(location).contains("/Events/");
        String txnId = location.substring(location.lastIndexOf('/') + 1);

        MvcResult pollRes = mockMvc.perform(get(scimPath(workspaceA, "/Events/" + txnId))
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isOk())
                .andReturn();
        ScimUser asyncUser = users.values().stream()
                .filter(u -> "async.sec".equals(u.getUserName()))
                .findFirst()
                .orElseThrow();
        assertBcryptMatch(asyncUser, pwAsync);

        // 6. Malformed/truncated PATCH with intervening "op" between "path" and "value" (both field orders)
        mockMvc.perform(patch(scimPath(workspaceA, "/Users/" + userId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content("{\"Operations\":[{\"path\":\"password\",\"op\":\"replace\",\"value\":\"" + pwMalformedPathOpVal))
                .andExpect(status().isBadRequest());
        mockMvc.perform(patch(scimPath(workspaceA, "/Users/" + userId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content("{\"Operations\":[{\"value\":\"" + pwMalformedValOpPath + "\",\"op\":\"replace\",\"path\":\"password\""))
                .andExpect(status().isBadRequest());

        // Verify zero cleartext leakage anywhere in entities, request logs, async events, or HTTP responses
        List<String> allSecrets = List.of(
                pwCreate, pwReplace, pwPatch, pwBulkPost, pwBulkPatch, pwAsync,
                pwMalformedPathOpVal, pwMalformedValOpPath);
        assertThat(requestLogs).isNotEmpty();
        boolean sawRedactedMarker = false;
        for (String secret : allSecrets) {
            for (ScimUser u : users.values()) {
                assertThat(u.getPassword()).doesNotContain(secret);
            }
            for (ScimRequestLog log : requestLogs) {
                if (log.getRequestBody() != null) {
                    assertThat(log.getRequestBody()).doesNotContain(secret);
                    if (log.getRequestBody().contains("[REDACTED]")) {
                        sawRedactedMarker = true;
                    }
                }
                if (log.getResponseBody() != null) {
                    assertThat(log.getResponseBody()).doesNotContain(secret);
                }
            }
            for (ScimAsyncEvent ev : asyncEvents.values()) {
                if (ev.getSetPayload() != null) {
                    assertThat(ev.getSetPayload()).doesNotContain(secret);
                }
            }
            assertThat(createRes.getResponse().getContentAsString()).doesNotContain(secret);
            assertThat(bulkRes.getResponse().getContentAsString()).doesNotContain(secret);
            assertThat(pollRes.getResponse().getContentAsString()).doesNotContain(secret);
        }
        assertThat(sawRedactedMarker).isTrue();
    }

    // ─── Group 2: Immutable Attribute Semantics on PUT & PATCH ───

    @Test
    // RFC7643-7-031493, RFC7644-3.5.1-2e5206, RFC7644-3.5.1-019f75, RFC7644-3.5.2-0cc87d
    void group2_immutableGroupMemberSemanticsOnPutAndPatch() throws Exception {
        ScimUser u1 = seedUser(workspaceA, "member.one", "Pass!1");
        ScimUser u2 = seedUser(workspaceA, "member.two", "Pass!2");
        ScimUser u3 = seedUser(workspaceA, "member.unset", "Pass!3");

        MvcResult createGroupRes = mockMvc.perform(post(scimPath(workspaceA, "/Groups"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "displayName", "ImmutableMembersGroup",
                                "members", List.of(Map.of("value", u1.getId().toString(), "type", "User"))))))
                .andExpect(status().isCreated())
                .andReturn();
        String groupId = (String) readJson(createGroupRes).get("id");

        // PUT keeping identical member value & type succeeds (200)
        mockMvc.perform(put(scimPath(workspaceA, "/Groups/" + groupId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "displayName", "ImmutableMembersGroup",
                                "members", List.of(Map.of("value", u1.getId().toString(), "type", "User"))))))
                .andExpect(status().isOk());

        // PUT keeping existing member with omitted type also succeeds (200)
        mockMvc.perform(put(scimPath(workspaceA, "/Groups/" + groupId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "displayName", "ImmutableMembersGroup",
                                "members", List.of(Map.of("value", u1.getId().toString()))))))
                .andExpect(status().isOk());

        // PUT changing existing member's type ("User" -> "Group") fails with 400 mutability
        mockMvc.perform(put(scimPath(workspaceA, "/Groups/" + groupId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "displayName", "ImmutableMembersGroup",
                                "members", List.of(Map.of("value", u1.getId().toString(), "type", "Group"))))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("mutability"));

        // PATCH replace or remove targeting .type, .value, or .$ref fails with 400 mutability
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

        // PATCH add new member object succeeds (200)
        mockMvc.perform(patch(scimPath(workspaceA, "/Groups/" + groupId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(PATCH_OP_SCHEMA),
                                "Operations", List.of(Map.of(
                                        "op", "add",
                                        "path", "members",
                                        "value", List.of(Map.of("value", u2.getId().toString(), "type", "User"))))))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.members.length()").value(2));

        // Seed a membership with unset memberType ("") and verify PATCH add sets it once, then rejects conflicting add
        ScimGroup storedGroup = groups.get(UUID.fromString(groupId));
        ScimGroupMembership unsetMembership = new ScimGroupMembership();
        unsetMembership.setId(UUID.randomUUID());
        unsetMembership.setGroup(storedGroup);
        unsetMembership.setMemberValue(u3.getId());
        unsetMembership.setMemberType("");
        unsetMembership.setDisplay(u3.getUserName());
        storedGroup.getMembers().add(unsetMembership);

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
    void group3_multiWorkspaceSubjectMappingIsolationAndTokenLifetime() throws Exception {
        // Verify SHA-256 token hash storage (never raw token)
        assertThat(tokenA.getTokenHash())
                .isEqualTo(TokenSecurityUtil.sha256Hex(rawTokenA))
                .isNotEqualTo(rawTokenA)
                .hasSize(64);

        // Create resources in Workspace B using Token B
        ScimUser userB = seedUser(workspaceB, "bravo.user", "SecretBravo!1");
        ScimGroup groupB = seedGroup(workspaceB, "BravoGroup");
        MvcResult asyncB = mockMvc.perform(post(scimPath(workspaceB, "/Users"))
                        .header("Authorization", "Bearer " + rawTokenB)
                        .header("Prefer", "respond-async")
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of("userName", "bravo.async"))))
                .andExpect(status().isAccepted())
                .andReturn();
        String locationB = asyncB.getResponse().getHeader("Location");
        String txnB = locationB.substring(locationB.lastIndexOf('/') + 1);

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
        mockMvc.perform(get(scimPath(workspaceB, "/Events/" + txnB)).header("Authorization", "Bearer " + rawTokenA))
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

        mockMvc.perform(get(scimPath(workspaceA, "/Events/" + txnB)).header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isNotFound());

        // 3. Token lifetime and revocation checks
        String futureRaw = "tok_future_" + UUID.randomUUID();
        seedToken(workspaceA, "Future Token", futureRaw, Instant.now().plus(2, ChronoUnit.HOURS), false);
        mockMvc.perform(get(scimPath(workspaceA, "/Users")).header("Authorization", "Bearer " + futureRaw))
                .andExpect(status().isOk());

        String expiredRaw = "tok_expired_" + UUID.randomUUID();
        seedToken(workspaceA, "Expired Token", expiredRaw, Instant.now().minus(5, ChronoUnit.MINUTES), false);
        mockMvc.perform(get(scimPath(workspaceA, "/Users")).header("Authorization", "Bearer " + expiredRaw))
                .andExpect(status().isUnauthorized());

        String revokedRaw = "tok_revoked_" + UUID.randomUUID();
        seedToken(workspaceA, "Revoked Token", revokedRaw, Instant.now().plus(2, ChronoUnit.HOURS), true);
        mockMvc.perform(get(scimPath(workspaceA, "/Users")).header("Authorization", "Bearer " + revokedRaw))
                .andExpect(status().isUnauthorized());
    }

    // ─── Group 4: Cursor Pagination Security ───

    @Test
    // RFC9865-5.2-230645
    void group4_cursorConfinementAcrossWorkspaces() throws Exception {
        seedUser(workspaceA, "alpha.1", "AlphaPass!1");
        seedUser(workspaceA, "alpha.2", "AlphaPass!2");
        seedUser(workspaceA, "alpha.3", "AlphaPass!3");
        seedUser(workspaceB, "bravo.only", "BravoPass!1");

        MvcResult page1A = mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("cursor", "")
                        .param("count", "1")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isOk())
                .andReturn();
        String cursorA = (String) readJson(page1A).get("nextCursor");
        assertThat(cursorA).isNotBlank();

        // Presenting Workspace A cursor on Workspace B with Token B must fail 400 invalidCursor and return zero Workspace A users
        MvcResult crossRes = mockMvc.perform(get(scimPath(workspaceB, "/Users"))
                        .param("cursor", cursorA)
                        .param("count", "1")
                        .header("Authorization", "Bearer " + rawTokenB))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("invalidCursor"))
                .andReturn();
        assertThat(crossRes.getResponse().getContentAsString())
                .doesNotContain("alpha.1")
                .doesNotContain("alpha.2")
                .doesNotContain("alpha.3");

        // Normal cursor pagination in Workspace B returns only Workspace B resources
        mockMvc.perform(get(scimPath(workspaceB, "/Users"))
                        .param("cursor", "")
                        .param("count", "10")
                        .header("Authorization", "Bearer " + rawTokenB))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalResults").value(1))
                .andExpect(jsonPath("$.Resources[0].userName").value("bravo.only"));
    }

    @Test
    // RFC9865-5.2-535e56
    void group4_cursorDeniedImmediatelyAfterTokenRevocationOrExpiry() throws Exception {
        seedUser(workspaceA, "page.user1", "Secret!1");
        seedUser(workspaceA, "page.user2", "Secret!2");

        MvcResult page1 = mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("cursor", "")
                        .param("count", "1")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isOk())
                .andReturn();
        String nextCursor = (String) readJson(page1).get("nextCursor");
        assertThat(nextCursor).isNotBlank();

        // Revoke Token A mid-pagination -> 401 and no Resources
        tokenA.setRevoked(true);
        MvcResult revokedPage2 = mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("cursor", nextCursor)
                        .param("count", "1")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isUnauthorized())
                .andReturn();
        assertThat(readJson(revokedPage2)).doesNotContainKey("Resources");

        // Unrevoke, then expire Token A mid-pagination -> 401 and no Resources
        tokenA.setRevoked(false);
        tokenA.setExpiresAt(Instant.now().minus(1, ChronoUnit.MINUTES));
        MvcResult expiredPage2 = mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("cursor", nextCursor)
                        .param("count", "1")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isUnauthorized())
                .andReturn();
        assertThat(readJson(expiredPage2)).doesNotContainKey("Resources");
    }

    @Test
    // RFC9865-5.2-826018
    void group4_cursorErrorsLeakZeroSensitiveData() throws Exception {
        String seededPassword = "TopSecretSeededPassword!888";
        ScimUser seededUser = seedUser(workspaceA, "confidential.user.alpha", seededPassword);

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
                SIMULATED_DB_SECRET,
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
        // Workspace A cursor presented in Workspace B
        errorResponses.add(mockMvc.perform(get(scimPath(workspaceB, "/Users"))
                        .param("cursor", validCursorA)
                        .param("count", "1")
                        .header("Authorization", "Bearer " + rawTokenB))
                .andExpect(status().isBadRequest())
                .andReturn());
        // Conflicting cursor + startIndex with negative count, non-numeric count, and count > maxPageSize
        errorResponses.add(mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("cursor", "")
                        .param("startIndex", "1")
                        .param("count", "-5")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isBadRequest())
                .andReturn());
        errorResponses.add(mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("cursor", "")
                        .param("count", "notAnInt")
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

        // Also verify negative count without startIndex (clamped to 0 per RFC 9865 §2) exposes zero resources/secrets
        MvcResult negCountRes = mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("cursor", "")
                        .param("count", "-5")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.itemsPerPage").value(0))
                .andExpect(jsonPath("$.Resources.length()").value(0))
                .andReturn();
        String negBody = negCountRes.getResponse().getContentAsString();
        for (String secret : whiteBoxSecrets) {
            assertThat(negBody).doesNotContain(secret);
        }
    }

    // ─── Group 5: Result Size Cap, Sanitized 500 Errors & Version-Agnostic $ref ───

    @Test
    // RFC7644-3.4.2.1-145a1a, RFC7644-3.12-40cb84
    void group5_maxResultsClampedOnIndexAndTooManyOnCursor() throws Exception {
        for (int i = 0; i < 205; i++) {
            seedUser(workspaceA, "cap.user." + i, null);
        }

        // Index pagination clamps count=500 to <= 200
        mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("count", "500")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalResults").value(205))
                .andExpect(jsonPath("$.itemsPerPage").value(200))
                .andExpect(jsonPath("$.Resources.length()").value(200));

        // Cursor pagination rejects count > maxPageSize (200) with 400 tooMany across /Users, /Groups, and /.search
        mockMvc.perform(get(scimPath(workspaceA, "/Users"))
                        .param("cursor", "")
                        .param("count", "201")
                        .header("Authorization", "Bearer " + rawTokenA))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("tooMany"));

        mockMvc.perform(get(scimPath(workspaceA, "/Groups"))
                        .param("cursor", "")
                        .param("count", "250")
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
    void group5_internal500ErrorSanitizedWithoutSqlOrExceptionLeak() throws Exception {
        failNextUserSaveWithTxError.set(true);

        MvcResult res = mockMvc.perform(post(scimPath(workspaceA, "/Users"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of("userName", "tx.fail.user"))))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.schemas[0]").value(ERROR_SCHEMA))
                .andExpect(jsonPath("$.status").value("500"))
                .andExpect(jsonPath("$.detail").value("Internal server error"))
                .andReturn();

        String body = res.getResponse().getContentAsString();
        assertThat(body)
                .doesNotContain("select ")
                .doesNotContain("insert ")
                .doesNotContain("jdbc:postgresql")
                .doesNotContain(SIMULATED_DB_SECRET)
                .doesNotContain("SQLException")
                .doesNotContain("Transaction error");
    }

    @Test
    // RFC7643-2.4-63934b
    void group5_versionAgnosticRefAcceptedNormalizedAndFiltered() throws Exception {
        ScimUser mgr1 = seedUser(workspaceA, "manager.one", "Pass!1");
        ScimUser mgr2 = seedUser(workspaceA, "manager.two", "Pass!2");
        ScimUser extraMember = seedUser(workspaceA, "member.extra", "Pass!3");

        // 1. $ref-only enterprise.manager on POST, PUT, and PATCH (without "value")
        MvcResult empRes = mockMvc.perform(post(scimPath(workspaceA, "/Users"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(ScimUserMapper.USER_SCHEMA, ScimUserMapper.ENTERPRISE_SCHEMA),
                                "userName", "employee.ref",
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
                                "userName", "employee.ref",
                                ScimUserMapper.ENTERPRISE_SCHEMA, Map.of(
                                        "manager", Map.of("$ref", "../Users/" + mgr2.getId()))))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$['" + ScimUserMapper.ENTERPRISE_SCHEMA + "'].manager.value").value(mgr2.getId().toString()));

        // PATCH with $ref-only unversioned /Users/<mgr1>
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
                                "displayName", "VersionAgnosticGroup",
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

        // PATCH add $ref-only member, then PATCH remove $ref-only member
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

        // PUT Group with $ref-only member
        mockMvc.perform(put(scimPath(workspaceA, "/Groups/" + grpId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "displayName", "VersionAgnosticGroup",
                                "members", List.of(Map.of("$ref", "https://idp.example.com/scim/v1/Users/" + empId))))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.members.length()").value(1))
                .andExpect(jsonPath("$.members[0].value").value(empId.toString()));

        // Bulk $ref-only bulkId resolution (/Users/bulkId:...)
        mockMvc.perform(post(scimPath(workspaceA, "/Bulk"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(BULK_REQUEST_SCHEMA),
                                "Operations", List.of(
                                        Map.of("method", "POST", "path", "/Users", "bulkId", "refBulkUser",
                                                "data", Map.of("userName", "bulk.ref.only")),
                                        Map.of("method", "POST", "path", "/Groups", "bulkId", "refBulkGroup",
                                                "data", Map.of(
                                                        "displayName", "BulkRefOnlyGroup",
                                                        "members", List.of(Map.of("$ref", "/Users/bulkId:refBulkUser")))))))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.Operations[0].status").value("201"))
                .andExpect(jsonPath("$.Operations[1].status").value("201"));

        // 3. Conflict & invalid $ref rejection (400 invalidValue) on both Group.members and enterprise.manager across POST, PUT, PATCH
        mockMvc.perform(post(scimPath(workspaceA, "/Groups"))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "displayName", "ConflictGroupPost",
                                "members", List.of(Map.of(
                                        "value", empId.toString(),
                                        "$ref", "https://idp.example.com/scim/v2/Users/" + mgr1.getId()))))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("invalidValue"));

        mockMvc.perform(put(scimPath(workspaceA, "/Groups/" + grpId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "displayName", "VersionAgnosticGroup",
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
                                "userName", "bad.mgr.post",
                                ScimUserMapper.ENTERPRISE_SCHEMA, Map.of(
                                        "manager", Map.of("value", mgr1.getId().toString(), "$ref", "/Users/" + mgr2.getId()))))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.scimType").value("invalidValue"));

        mockMvc.perform(put(scimPath(workspaceA, "/Users/" + empId))
                        .header("Authorization", "Bearer " + rawTokenA)
                        .contentType(SCIM_CONTENT_TYPE)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "schemas", List.of(ScimUserMapper.USER_SCHEMA, ScimUserMapper.ENTERPRISE_SCHEMA),
                                "userName", "employee.ref",
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

        // 4. Cross-version & relative $ref filtering across manager.$ref, members.$ref, and groups.$ref
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
                    .andExpect(jsonPath("$.Resources[0].userName").value("employee.ref"));
        }

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

    // ─── In-memory Harness Helpers ───

    @SuppressWarnings("unchecked")
    private void wireInMemoryRepositories() {
        when(workspaceRepository.findById(any(UUID.class)))
                .thenAnswer(inv -> Optional.ofNullable(workspaces.get(inv.getArgument(0))));
        when(workspaceRepository.existsById(any(UUID.class)))
                .thenAnswer(inv -> workspaces.containsKey(inv.getArgument(0)));
        when(workspaceRepository.getReferenceById(any(UUID.class)))
                .thenAnswer(inv -> workspaces.get(inv.getArgument(0)));

        when(tokenRepository.findByTokenHashAndNotRevoked(any(String.class)))
                .thenAnswer(inv -> {
                    String hash = inv.getArgument(0);
                    return tokens.values().stream()
                            .filter(t -> !t.isRevoked() && hash.equals(t.getTokenHash()))
                            .findFirst();
                });

        when(userRepository.save(any(ScimUser.class))).thenAnswer(inv -> {
            if (failNextUserSaveWithTxError.compareAndSet(true, false)) {
                SQLException sqlEx = new SQLException(
                        "ERROR: insert into scim_users failed; password=" + SIMULATED_DB_SECRET + "; jdbc:postgresql://db:5432/scim");
                throw new TransactionSystemException("JPA commit failed", sqlEx);
            }
            ScimUser u = inv.getArgument(0);
            Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
            if (u.getId() == null) {
                u.setId(UUID.randomUUID());
            }
            if (u.getCreatedAt() == null) {
                u.setCreatedAt(now);
            }
            u.setLastModified(now);
            u.setVersion(u.getVersion() == null ? 0L : u.getVersion() + 1L);
            users.put(u.getId(), u);
            return u;
        });
        when(userRepository.findByIdAndWorkspaceId(any(UUID.class), any(UUID.class)))
                .thenAnswer(inv -> {
                    UUID id = inv.getArgument(0);
                    UUID wsId = inv.getArgument(1);
                    ScimUser u = users.get(id);
                    return (u != null && u.getWorkspace() != null && wsId.equals(u.getWorkspace().getId()))
                            ? Optional.of(u)
                            : Optional.empty();
                });
        when(userRepository.existsByUserNameIgnoreCaseAndWorkspaceId(any(String.class), any(UUID.class)))
                .thenAnswer(inv -> {
                    String un = inv.getArgument(0);
                    UUID wsId = inv.getArgument(1);
                    return users.values().stream().anyMatch(u ->
                            u.getWorkspace() != null
                                    && wsId.equals(u.getWorkspace().getId())
                                    && u.getUserName() != null
                                    && u.getUserName().equalsIgnoreCase(un));
                });
        when(userRepository.findByUserNameIgnoreCaseAndWorkspaceId(any(String.class), any(UUID.class)))
                .thenAnswer(inv -> {
                    String un = inv.getArgument(0);
                    UUID wsId = inv.getArgument(1);
                    return users.values().stream().filter(u ->
                            u.getWorkspace() != null
                                    && wsId.equals(u.getWorkspace().getId())
                                    && u.getUserName() != null
                                    && u.getUserName().equalsIgnoreCase(un)).findFirst();
                });
        doAnswer(inv -> {
            ScimUser u = inv.getArgument(0);
            if (u != null && u.getId() != null) {
                users.remove(u.getId());
            }
            return null;
        }).when(userRepository).delete(any(ScimUser.class));

        when(groupRepository.save(any(ScimGroup.class))).thenAnswer(inv -> {
            ScimGroup g = inv.getArgument(0);
            Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
            if (g.getId() == null) {
                g.setId(UUID.randomUUID());
            }
            if (g.getCreatedAt() == null) {
                g.setCreatedAt(now);
            }
            g.setLastModified(now);
            g.setVersion(g.getVersion() == null ? 0L : g.getVersion() + 1L);
            if (g.getMembers() != null) {
                for (ScimGroupMembership m : g.getMembers()) {
                    if (m.getId() == null) {
                        m.setId(UUID.randomUUID());
                    }
                    m.setGroup(g);
                }
            }
            groups.put(g.getId(), g);
            return g;
        });
        when(groupRepository.findByIdAndWorkspaceId(any(UUID.class), any(UUID.class)))
                .thenAnswer(inv -> {
                    UUID id = inv.getArgument(0);
                    UUID wsId = inv.getArgument(1);
                    ScimGroup g = groups.get(id);
                    return (g != null && g.getWorkspace() != null && wsId.equals(g.getWorkspace().getId()))
                            ? Optional.of(g)
                            : Optional.empty();
                });
        when(groupRepository.existsByDisplayNameAndWorkspaceId(any(String.class), any(UUID.class)))
                .thenAnswer(inv -> {
                    String dn = inv.getArgument(0);
                    UUID wsId = inv.getArgument(1);
                    return groups.values().stream().anyMatch(g ->
                            g.getWorkspace() != null
                                    && wsId.equals(g.getWorkspace().getId())
                                    && g.getDisplayName() != null
                                    && g.getDisplayName().equals(dn));
                });
        when(groupRepository.findByDisplayNameAndWorkspaceId(any(String.class), any(UUID.class)))
                .thenAnswer(inv -> {
                    String dn = inv.getArgument(0);
                    UUID wsId = inv.getArgument(1);
                    return groups.values().stream().filter(g ->
                            g.getWorkspace() != null
                                    && wsId.equals(g.getWorkspace().getId())
                                    && g.getDisplayName() != null
                                    && g.getDisplayName().equals(dn)).findFirst();
                });
        doAnswer(inv -> {
            ScimGroup g = inv.getArgument(0);
            if (g != null && g.getId() != null) {
                groups.remove(g.getId());
            }
            return null;
        }).when(groupRepository).delete(any(ScimGroup.class));

        when(membershipRepository.findByMemberValueAndWorkspaceId(any(UUID.class), any(UUID.class)))
                .thenAnswer(inv -> {
                    UUID memberId = inv.getArgument(0);
                    UUID wsId = inv.getArgument(1);
                    List<ScimGroupMembership> found = new ArrayList<>();
                    for (ScimGroup g : groups.values()) {
                        if (g.getWorkspace() == null || !wsId.equals(g.getWorkspace().getId())) {
                            continue;
                        }
                        for (ScimGroupMembership m : g.getMembers()) {
                            if (memberId.equals(m.getMemberValue())) {
                                found.add(m);
                            }
                        }
                    }
                    return found;
                });
        when(membershipRepository.findByMemberValueInAndWorkspaceId(any(List.class), any(UUID.class)))
                .thenAnswer(inv -> {
                    @SuppressWarnings("unchecked")
                    List<UUID> memberIds = inv.getArgument(0);
                    UUID wsId = inv.getArgument(1);
                    List<ScimGroupMembership> found = new ArrayList<>();
                    for (ScimGroup g : groups.values()) {
                        if (g.getWorkspace() == null || !wsId.equals(g.getWorkspace().getId())) {
                            continue;
                        }
                        for (ScimGroupMembership m : g.getMembers()) {
                            if (memberIds.contains(m.getMemberValue())) {
                                found.add(m);
                            }
                        }
                    }
                    return found;
                });
        when(membershipRepository.deleteByMemberValueAndWorkspaceId(any(UUID.class), any(UUID.class)))
                .thenAnswer(inv -> {
                    UUID memberId = inv.getArgument(0);
                    UUID wsId = inv.getArgument(1);
                    long removed = 0;
                    for (ScimGroup g : groups.values()) {
                        if (g.getWorkspace() == null || !wsId.equals(g.getWorkspace().getId())) {
                            continue;
                        }
                        int before = g.getMembers().size();
                        g.getMembers().removeIf(m -> memberId.equals(m.getMemberValue()));
                        removed += (before - g.getMembers().size());
                    }
                    return removed;
                });

        when(requestLogRepository.save(any(ScimRequestLog.class)))
                .thenAnswer(inv -> {
                    ScimRequestLog log = inv.getArgument(0);
                    if (log.getId() == null) {
                        log.setId(UUID.randomUUID());
                    }
                    if (log.getCreatedAt() == null) {
                        log.setCreatedAt(Instant.now().truncatedTo(ChronoUnit.MICROS));
                    }
                    requestLogs.add(log);
                    return log;
                });

        when(asyncEventRepository.save(any(ScimAsyncEvent.class)))
                .thenAnswer(inv -> {
                    ScimAsyncEvent ev = inv.getArgument(0);
                    if (ev.getTxnId() == null) {
                        ev.setTxnId(UUID.randomUUID());
                    }
                    if (ev.getCreatedAt() == null) {
                        ev.setCreatedAt(Instant.now().truncatedTo(ChronoUnit.MICROS));
                    }
                    asyncEvents.put(ev.getTxnId(), ev);
                    return ev;
                });
        when(asyncEventRepository.saveAndFlush(any(ScimAsyncEvent.class)))
                .thenAnswer(inv -> asyncEventRepository.save(inv.getArgument(0)));
        when(asyncEventRepository.findById(any(UUID.class)))
                .thenAnswer(inv -> Optional.ofNullable(asyncEvents.get(inv.getArgument(0))));
        when(asyncEventRepository.findByTxnIdAndWorkspaceId(any(UUID.class), any(UUID.class)))
                .thenAnswer(inv -> {
                    UUID txnId = inv.getArgument(0);
                    UUID wsId = inv.getArgument(1);
                    ScimAsyncEvent ev = asyncEvents.get(txnId);
                    return (ev != null && ev.getWorkspace() != null && wsId.equals(ev.getWorkspace().getId()))
                            ? Optional.of(ev)
                            : Optional.empty();
                });
        when(asyncEventRepository.transitionPendingToCompleted(any(UUID.class), any(), any(Instant.class), any(String.class)))
                .thenAnswer(inv -> {
                    UUID txnId = inv.getArgument(0);
                    UUID resId = inv.getArgument(1);
                    Instant completedAt = inv.getArgument(2);
                    String payload = inv.getArgument(3);
                    ScimAsyncEvent ev = asyncEvents.get(txnId);
                    if (ev != null && "PENDING".equals(ev.getStatus())) {
                        ev.setStatus("COMPLETED");
                        if (resId != null) {
                            ev.setResourceId(resId);
                        }
                        ev.setCompletedAt(completedAt);
                        ev.setSetPayload(payload);
                        return 1;
                    }
                    return 0;
                });
        when(asyncEventRepository.transitionPendingToFailed(any(UUID.class), any(Instant.class), any(String.class)))
                .thenAnswer(inv -> {
                    UUID txnId = inv.getArgument(0);
                    Instant completedAt = inv.getArgument(1);
                    String payload = inv.getArgument(2);
                    ScimAsyncEvent ev = asyncEvents.get(txnId);
                    if (ev != null && "PENDING".equals(ev.getStatus())) {
                        ev.setStatus("FAILED");
                        ev.setCompletedAt(completedAt);
                        ev.setSetPayload(payload);
                        return 1;
                    }
                    return 0;
                });
    }

    private Workspace seedWorkspace(String name) {
        Workspace ws = new Workspace();
        ws.setId(UUID.randomUUID());
        ws.setName(name + "-" + UUID.randomUUID());
        ws.setCreatedByUsername("admin@example.com");
        ws.setCreatedAt(Instant.now().truncatedTo(ChronoUnit.MICROS));
        ws.setUpdatedAt(ws.getCreatedAt());
        workspaces.put(ws.getId(), ws);
        return ws;
    }

    private WorkspaceToken seedToken(Workspace ws, String name, String rawToken, Instant expiresAt, boolean revoked) {
        WorkspaceToken tok = new WorkspaceToken();
        tok.setId(UUID.randomUUID());
        tok.setWorkspace(ws);
        tok.setName(name);
        tok.setTokenHash(TokenSecurityUtil.sha256Hex(rawToken));
        tok.setExpiresAt(expiresAt);
        tok.setRevoked(revoked);
        tok.setCreatedAt(Instant.now().truncatedTo(ChronoUnit.MICROS));
        tok.setUpdatedAt(tok.getCreatedAt());
        tokens.put(tok.getId(), tok);
        return tok;
    }

    private ScimUser seedUser(Workspace ws, String userName, String rawPassword) {
        ScimUser u = new ScimUser();
        u.setWorkspace(ws);
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("userName", userName);
        if (rawPassword != null) {
            input.put("password", rawPassword);
        }
        ScimUserMapper.applyFromScimInput(u, input);
        return userRepository.save(u);
    }

    private ScimGroup seedGroup(Workspace ws, String displayName) {
        ScimGroup g = new ScimGroup();
        g.setWorkspace(ws);
        g.setDisplayName(displayName);
        return groupRepository.save(g);
    }

    private void assertBcryptMatch(ScimUser user, String expectedRawPassword) {
        assertThat(user).isNotNull();
        assertThat(user.getPassword()).isNotNull();
        assertThat(user.getPassword().startsWith("$2a$") || user.getPassword().startsWith("$2b$")).isTrue();
        assertThat(passwordEncoder.matches(expectedRawPassword, user.getPassword())).isTrue();
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
