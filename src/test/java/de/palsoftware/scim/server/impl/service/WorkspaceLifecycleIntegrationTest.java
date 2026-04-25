package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.ScimServerApplication;
import de.palsoftware.scim.server.impl.PostgresIntegrationTestSupport;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.transaction.annotation.Transactional;

import jakarta.persistence.EntityManager;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(classes = {
        ScimServerApplication.class,
        WorkspaceLifecycleIntegrationTest.FixedClockConfiguration.class
}, properties = {
        "ACTUATOR_API_KEY=test-key",
        "spring.jpa.hibernate.ddl-auto=validate",
    "app.cleanup.workspace.cron=0 0 0 1 1 *",
    "app.cleanup.workspace.stale-after=P3M"
})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@Transactional
class WorkspaceLifecycleIntegrationTest extends PostgresIntegrationTestSupport {

    @Autowired
    private WorkspaceRepository workspaceRepository;

    @Autowired
    private ScimUserService scimUserService;

    @Autowired
    private WorkspaceCleanupService workspaceCleanupService;

    @Autowired
    private MutableClock clock;

    @Autowired
    private EntityManager entityManager;

    @Test
    void createUserUpdatesWorkspaceUpdatedAt() {
        Workspace workspace = new Workspace();
        workspace.setName("touch-" + UUID.randomUUID());
        workspace.setDescription("touch test");
        workspace = workspaceRepository.saveAndFlush(workspace);

        Instant baseline = Instant.parse("2025-01-01T00:00:00Z");
        workspaceRepository.touchUpdatedAt(workspace.getId(), baseline);
        clock.setInstant(baseline.plus(Duration.ofHours(6)));

        scimUserService.createUser(workspace.getId(), Map.of("userName", "alice@example.com"));

        entityManager.flush();
        entityManager.clear();

        Instant updatedAt = workspaceRepository.findById(workspace.getId())
                .orElseThrow()
                .getUpdatedAt();

        assertEquals(clock.instant(), updatedAt);
    }

    @Test
    void cleanupDeletesOnlyWorkspacesOlderThanConfiguredWindow() {
        Workspace staleWorkspace = new Workspace();
        staleWorkspace.setName("stale-" + UUID.randomUUID());
        staleWorkspace = workspaceRepository.saveAndFlush(staleWorkspace);

        Workspace freshWorkspace = new Workspace();
        freshWorkspace.setName("fresh-" + UUID.randomUUID());
        freshWorkspace = workspaceRepository.saveAndFlush(freshWorkspace);

        workspaceRepository.touchUpdatedAt(staleWorkspace.getId(), Instant.parse("2025-10-01T00:00:00Z"));
        workspaceRepository.touchUpdatedAt(freshWorkspace.getId(), Instant.parse("2026-02-20T00:00:00Z"));

        int deletedCount = workspaceCleanupService.deleteStaleWorkspaces(Instant.parse("2026-03-19T00:00:00Z"));

        entityManager.flush();
        entityManager.clear();

        assertEquals(1, deletedCount);
        assertFalse(workspaceRepository.findById(staleWorkspace.getId()).isPresent());
        assertTrue(workspaceRepository.findById(freshWorkspace.getId()).isPresent());
    }

    @TestConfiguration
    static class FixedClockConfiguration {

        @Bean
        @Primary
        MutableClock mutableClock() {
            return new MutableClock(Instant.parse("2026-03-19T00:00:00Z"), ZoneOffset.UTC);
        }
    }

    static final class MutableClock extends Clock {

        private Instant instant;
        private final ZoneId zoneId;

        MutableClock(Instant instant, ZoneId zoneId) {
            this.instant = instant;
            this.zoneId = zoneId;
        }

        void setInstant(Instant instant) {
            this.instant = instant;
        }

        @Override
        public ZoneId getZone() {
            return zoneId;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return new MutableClock(instant, zone);
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}