package de.palsoftware.scim.server.impl.repository;

import de.palsoftware.scim.server.impl.entity.ScimAsyncEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ScimAsyncEventRepository extends JpaRepository<ScimAsyncEvent, UUID> {

    @Query("SELECT e FROM ScimAsyncEvent e WHERE e.txnId = :txnId AND e.workspace.id = :workspaceId")
    Optional<ScimAsyncEvent> findByTxnIdAndWorkspaceId(@Param("txnId") UUID txnId, @Param("workspaceId") UUID workspaceId);

    @Query("SELECT e FROM ScimAsyncEvent e WHERE e.workspace.id = :workspaceId ORDER BY e.createdAt DESC")
    List<ScimAsyncEvent> findByWorkspaceId(@Param("workspaceId") UUID workspaceId);

    @Modifying
    @Query("DELETE FROM ScimAsyncEvent e WHERE e.workspace.id = :workspaceId")
    int deleteAllByWorkspaceId(@Param("workspaceId") UUID workspaceId);

    @Modifying
    @Query(value = """
        DELETE FROM scim_async_events
        WHERE workspace_id = :workspaceId
          AND status IN ('COMPLETED', 'FAILED')
          AND txn_id IN (
              SELECT txn_id
              FROM scim_async_events
              WHERE workspace_id = :workspaceId
                AND status IN ('COMPLETED', 'FAILED')
              ORDER BY created_at DESC, txn_id DESC
              OFFSET :maxCount
              LIMIT :batchSize
          )
        """, nativeQuery = true)
    int deleteOldTerminalEventsByWorkspaceIdNative(
            @Param("workspaceId") UUID workspaceId,
            @Param("maxCount") int maxCount,
            @Param("batchSize") int batchSize);

    default int deleteOldTerminalEventsByWorkspaceIdNative(UUID workspaceId, int maxCount) {
        return deleteOldTerminalEventsByWorkspaceIdNative(workspaceId, maxCount, 5000);
    }

    @Query("SELECT e FROM ScimAsyncEvent e WHERE e.status = 'PENDING' AND e.createdAt < :cutoff ORDER BY e.createdAt ASC")
    List<ScimAsyncEvent> findStalePendingEvents(@Param("cutoff") Instant cutoff);

    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE ScimAsyncEvent e SET e.createdAt = :heartbeatAt WHERE e.txnId IN :txnIds AND e.status = 'PENDING'")
    int touchInFlightPendingEvents(
            @Param("txnIds") java.util.Collection<UUID> txnIds,
            @Param("heartbeatAt") Instant heartbeatAt
    );

    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE ScimAsyncEvent e SET e.status = 'COMPLETED', e.resourceId = COALESCE(:resourceId, e.resourceId), e.completedAt = :completedAt, e.setPayload = :setPayload WHERE e.txnId = :txnId AND e.status = 'PENDING'")
    int transitionPendingToCompleted(
            @Param("txnId") UUID txnId,
            @Param("resourceId") UUID resourceId,
            @Param("completedAt") Instant completedAt,
            @Param("setPayload") String setPayload
    );

    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE ScimAsyncEvent e SET e.status = 'FAILED', e.completedAt = :completedAt, e.setPayload = :setPayload WHERE e.txnId = :txnId AND e.status = 'PENDING'")
    int transitionPendingToFailed(@Param("txnId") UUID txnId,
                                  @Param("completedAt") Instant completedAt,
                                  @Param("setPayload") String setPayload);
}
