package de.palsoftware.scim.server.impl.repository;

import de.palsoftware.scim.server.impl.model.ScimRequestLog;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ScimRequestLogRepository extends JpaRepository<ScimRequestLog, UUID> {
    Page<ScimRequestLog> findByWorkspace_IdOrderByCreatedAtDesc(UUID workspaceId, Pageable pageable);

    @Modifying
    @Query("delete from ScimRequestLog log where log.workspace.id = :workspaceId")
    long deleteByWorkspaceId(@Param("workspaceId") UUID workspaceId);

    @Modifying
    @Query(value = """
        DELETE FROM scim_request_logs
        WHERE workspace_id = :workspaceId
          AND id IN (
              SELECT id
              FROM scim_request_logs
              WHERE workspace_id = :workspaceId
              ORDER BY created_at DESC, id DESC
              OFFSET :maxCount
              LIMIT :batchSize
          )
        """, nativeQuery = true)
    int deleteOldLogsByWorkspaceIdNative(
            @Param("workspaceId") UUID workspaceId,
            @Param("maxCount") int maxCount,
            @Param("batchSize") int batchSize);

    default int deleteOldLogsByWorkspaceIdNative(UUID workspaceId, int maxCount) {
        return deleteOldLogsByWorkspaceIdNative(workspaceId, maxCount, 5000);
    }
}
