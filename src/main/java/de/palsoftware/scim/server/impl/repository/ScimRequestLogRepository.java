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
}
