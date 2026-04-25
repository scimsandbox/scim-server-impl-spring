package de.palsoftware.scim.server.impl.repository;

import de.palsoftware.scim.server.impl.model.ScimGroup;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ScimGroupRepository extends JpaRepository<ScimGroup, UUID>, JpaSpecificationExecutor<ScimGroup> {

    Optional<ScimGroup> findByIdAndWorkspaceId(UUID id, UUID workspaceId);

    Optional<ScimGroup> findByDisplayNameAndWorkspaceId(String displayName, UUID workspaceId);

    boolean existsByDisplayNameAndWorkspaceId(String displayName, UUID workspaceId);

    java.util.List<ScimGroup> findByWorkspaceId(UUID workspaceId);

    Page<ScimGroup> findByWorkspaceId(UUID workspaceId, Pageable pageable);

        Page<ScimGroup> findByWorkspaceIdAndDisplayNameContainingIgnoreCaseOrWorkspaceIdAndExternalIdContainingIgnoreCase(
            UUID workspaceId,
            String displayName,
            UUID workspaceIdForExternalId,
            String externalId,
            Pageable pageable);

    long countByWorkspaceId(UUID workspaceId);

    @Query("SELECT g.id FROM ScimGroup g WHERE g.workspace.id = :workspaceId")
    List<UUID> findIdsByWorkspaceId(@Param("workspaceId") UUID workspaceId);

    @Modifying
    @Query("DELETE FROM ScimGroup g WHERE g.workspace.id = :workspaceId")
    int deleteAllByWorkspaceId(@Param("workspaceId") UUID workspaceId);
}
