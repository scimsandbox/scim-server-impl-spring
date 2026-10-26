package de.palsoftware.scim.server.impl.repository;

import de.palsoftware.scim.server.impl.entity.ScimAsyncEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

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
}
