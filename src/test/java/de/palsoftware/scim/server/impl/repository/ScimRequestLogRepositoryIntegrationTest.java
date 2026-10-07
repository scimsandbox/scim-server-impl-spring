package de.palsoftware.scim.server.impl.repository;

import de.palsoftware.scim.server.impl.PostgresIntegrationTestSupport;
import de.palsoftware.scim.server.impl.ScimServerApplication;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.service.RequestLogCleanupService;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = ScimServerApplication.class, properties = {
        "ACTUATOR_API_KEY=test-key",
        "spring.jpa.hibernate.ddl-auto=validate"
})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@Transactional
class ScimRequestLogRepositoryIntegrationTest extends PostgresIntegrationTestSupport {

    @Autowired
    private ScimRequestLogRepository logRepository;

    @Autowired
    private WorkspaceRepository workspaceRepository;

    @Autowired
    private RequestLogCleanupService cleanupService;

    @Autowired
    private EntityManager entityManager;

    private void insertLog(UUID id, UUID workspaceId, Instant createdAt) {
        entityManager.createNativeQuery("""
            INSERT INTO scim_request_logs (id, workspace_id, http_method, request_path, http_status, created_at)
            VALUES (:id, :workspaceId, 'GET', '/Users', 200, :createdAt)
        """)
        .setParameter("id", id)
        .setParameter("workspaceId", workspaceId)
        .setParameter("createdAt", Timestamp.from(createdAt))
        .executeUpdate();
    }

    @SuppressWarnings("unchecked")
    private List<UUID> findLogIds(UUID workspaceId) {
        return entityManager.createNativeQuery("""
            SELECT id FROM scim_request_logs
            WHERE workspace_id = :workspaceId
            ORDER BY created_at DESC, id DESC
        """)
        .setParameter("workspaceId", workspaceId)
        .getResultList();
    }

    private Workspace createWorkspace(String name) {
        Workspace ws = new Workspace();
        ws.setName(name + "-" + UUID.randomUUID());
        return workspaceRepository.saveAndFlush(ws);
    }

    @Test
    void deleteOldLogs_exactRetention_retainsNewestRecords() {
        Workspace ws = createWorkspace("retention");
        Instant base = Instant.now().truncatedTo(ChronoUnit.SECONDS);

        UUID log1 = UUID.randomUUID();
        UUID log2 = UUID.randomUUID();
        UUID log3 = UUID.randomUUID();
        UUID log4 = UUID.randomUUID();
        UUID log5 = UUID.randomUUID();

        insertLog(log1, ws.getId(), base.minusSeconds(50));
        insertLog(log2, ws.getId(), base.minusSeconds(40));
        insertLog(log3, ws.getId(), base.minusSeconds(30));
        insertLog(log4, ws.getId(), base.minusSeconds(20));
        insertLog(log5, ws.getId(), base.minusSeconds(10));

        entityManager.flush();
        entityManager.clear();

        int deleted = logRepository.deleteOldLogsByWorkspaceIdNative(ws.getId(), 2, 100);
        assertThat(deleted).isEqualTo(3);

        List<UUID> remaining = findLogIds(ws.getId());
        assertThat(remaining).containsExactly(log5, log4);
    }

    @Test
    void deleteOldLogs_workspaceIsolation_preservesOtherWorkspaces() {
        Workspace ws1 = createWorkspace("ws1");
        Workspace ws2 = createWorkspace("ws2");
        Instant base = Instant.now().truncatedTo(ChronoUnit.SECONDS);

        UUID ws1Log1 = UUID.randomUUID();
        UUID ws1Log2 = UUID.randomUUID();
        UUID ws1Log3 = UUID.randomUUID();
        UUID ws1Log4 = UUID.randomUUID();
        UUID ws1Log5 = UUID.randomUUID();

        insertLog(ws1Log1, ws1.getId(), base.minusSeconds(50));
        insertLog(ws1Log2, ws1.getId(), base.minusSeconds(40));
        insertLog(ws1Log3, ws1.getId(), base.minusSeconds(30));
        insertLog(ws1Log4, ws1.getId(), base.minusSeconds(20));
        insertLog(ws1Log5, ws1.getId(), base.minusSeconds(10));

        UUID ws2Log1 = UUID.randomUUID();
        UUID ws2Log2 = UUID.randomUUID();
        UUID ws2Log3 = UUID.randomUUID();

        insertLog(ws2Log1, ws2.getId(), base.minusSeconds(25));
        insertLog(ws2Log2, ws2.getId(), base.minusSeconds(15));
        insertLog(ws2Log3, ws2.getId(), base.minusSeconds(5));

        entityManager.flush();
        entityManager.clear();

        int deleted = logRepository.deleteOldLogsByWorkspaceIdNative(ws1.getId(), 2, 100);
        assertThat(deleted).isEqualTo(3);

        List<UUID> remainingWs1 = findLogIds(ws1.getId());
        assertThat(remainingWs1).containsExactly(ws1Log5, ws1Log4);

        List<UUID> remainingWs2 = findLogIds(ws2.getId());
        assertThat(remainingWs2).containsExactly(ws2Log3, ws2Log2, ws2Log1);
    }

    @Test
    void deleteOldLogs_tieBreak_resolvesIdenticalTimestampsByIdDesc() {
        Workspace ws = createWorkspace("tiebreak");
        Instant sameTimestamp = Instant.now().truncatedTo(ChronoUnit.SECONDS);

        UUID idSmall = UUID.fromString("00000000-0000-0000-0000-000000000001");
        UUID idLarge = UUID.fromString("00000000-0000-0000-0000-000000000002");

        insertLog(idSmall, ws.getId(), sameTimestamp);
        insertLog(idLarge, ws.getId(), sameTimestamp);

        entityManager.flush();
        entityManager.clear();

        int deleted = logRepository.deleteOldLogsByWorkspaceIdNative(ws.getId(), 1, 100);
        assertThat(deleted).isEqualTo(1);

        List<UUID> remaining = findLogIds(ws.getId());
        assertThat(remaining).containsExactly(idLarge);
    }

    @Test
    void deleteOldLogs_underThreshold_isNoOp() {
        Workspace ws = createWorkspace("under-threshold");
        Instant base = Instant.now().truncatedTo(ChronoUnit.SECONDS);

        UUID log1 = UUID.randomUUID();
        UUID log2 = UUID.randomUUID();

        insertLog(log1, ws.getId(), base.minusSeconds(20));
        insertLog(log2, ws.getId(), base.minusSeconds(10));

        entityManager.flush();
        entityManager.clear();

        int deleted = logRepository.deleteOldLogsByWorkspaceIdNative(ws.getId(), 10, 100);
        assertThat(deleted).isZero();

        List<UUID> remaining = findLogIds(ws.getId());
        assertThat(remaining).containsExactly(log2, log1);
    }

    @Test
    void deleteOldLogs_batchingLoop_prunesAcrossMultipleBatches() {
        Workspace ws = createWorkspace("batching");
        Instant base = Instant.now().truncatedTo(ChronoUnit.SECONDS);

        UUID log1 = UUID.randomUUID();
        UUID log2 = UUID.randomUUID();
        UUID log3 = UUID.randomUUID();
        UUID log4 = UUID.randomUUID();
        UUID log5 = UUID.randomUUID();

        insertLog(log1, ws.getId(), base.minusSeconds(50));
        insertLog(log2, ws.getId(), base.minusSeconds(40));
        insertLog(log3, ws.getId(), base.minusSeconds(30));
        insertLog(log4, ws.getId(), base.minusSeconds(20));
        insertLog(log5, ws.getId(), base.minusSeconds(10));

        entityManager.flush();
        entityManager.clear();

        // maxLogsToKeep = 2, batchSize = 2 -> 3 excess logs pruned across 2 batches (2 + 1)
        int totalDeleted = cleanupService.deleteOldRequestLogsForWorkspace(ws.getId(), 2, 2);
        assertThat(totalDeleted).isEqualTo(3);

        List<UUID> remaining = findLogIds(ws.getId());
        assertThat(remaining).containsExactly(log5, log4);
    }
}
