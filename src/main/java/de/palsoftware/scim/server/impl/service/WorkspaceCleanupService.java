package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionOperations;

import java.time.Clock;
import java.time.Instant;
import java.time.Period;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

@Service
public class WorkspaceCleanupService {

    private static final Logger logger = LoggerFactory.getLogger(WorkspaceCleanupService.class);

    private final WorkspaceRepository workspaceRepository;
    private final TransactionOperations transactionOperations;
    private final Clock clock;
    private final boolean cleanupEnabled;
    private final Period staleAfter;

    public WorkspaceCleanupService(WorkspaceRepository workspaceRepository,
            TransactionOperations transactionOperations,
            Clock clock,
            @Value("${app.cleanup.workspace.enabled}") boolean cleanupEnabled,
            @Value("${app.cleanup.workspace.stale-after}") String staleAfterValue) {
        this.workspaceRepository = workspaceRepository;
        this.transactionOperations = transactionOperations;
        this.clock = clock;
        this.cleanupEnabled = cleanupEnabled;
        this.staleAfter = Period.parse(staleAfterValue);
    }

    @Scheduled(cron = "${app.cleanup.workspace.cron}", zone = "${app.cleanup.workspace.zone}")
    public void deleteStaleWorkspacesOnSchedule() {
        if (!cleanupEnabled) {
            return;
        }
        Integer deletedCount = transactionOperations.execute(status -> deleteStaleWorkspaces(Instant.now(clock)));
        if (deletedCount != null && deletedCount > 0) {
            logger.info("Deleted {} stale workspaces older than {}", deletedCount, staleAfter);
        }
    }

    public int deleteStaleWorkspaces(Instant now) {
        Instant cutoff = ZonedDateTime.ofInstant(now, ZoneOffset.UTC)
                .minus(staleAfter)
                .toInstant();
        return workspaceRepository.deleteByUpdatedAtBefore(cutoff);
    }
}