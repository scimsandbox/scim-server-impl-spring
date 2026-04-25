package de.palsoftware.scim.server.impl.repository;

import de.palsoftware.scim.server.impl.model.Workspace;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface WorkspaceRepository extends JpaRepository<Workspace, UUID> {
    Optional<Workspace> findByIdAndCreatedByUsername(UUID id, String createdByUsername);

    List<Workspace> findByCreatedByUsernameOrderByCreatedAtDesc(String createdByUsername);

    @Query("""
        SELECT w FROM Workspace w
        ORDER BY w.createdAt DESC
    """)
    List<Workspace> findAllOrderByCreatedAtDesc();

    @Modifying(flushAutomatically = true)
    @Query("""
        UPDATE Workspace w
        SET w.updatedAt = :updatedAt
        WHERE w.id = :workspaceId
    """)
    int touchUpdatedAt(@Param("workspaceId") UUID workspaceId, @Param("updatedAt") Instant updatedAt);

    @Modifying(flushAutomatically = true)
    @Query("""
        DELETE FROM Workspace w
        WHERE w.updatedAt < :cutoff
    """)
    int deleteByUpdatedAtBefore(@Param("cutoff") Instant cutoff);

    boolean existsByNameAndCreatedByUsername(String name, String createdByUsername);
}
