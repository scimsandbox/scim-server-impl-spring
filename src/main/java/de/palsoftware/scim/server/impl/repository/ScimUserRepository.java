package de.palsoftware.scim.server.impl.repository;

import de.palsoftware.scim.server.impl.model.ScimUser;
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

public interface ScimUserRepository extends JpaRepository<ScimUser, UUID>, JpaSpecificationExecutor<ScimUser> {

    Optional<ScimUser> findByIdAndWorkspaceId(UUID id, UUID workspaceId);

    Optional<ScimUser> findByUserNameIgnoreCaseAndWorkspaceId(String userName, UUID workspaceId);

    boolean existsByUserNameIgnoreCaseAndWorkspaceId(String userName, UUID workspaceId);

    List<ScimUser> findByWorkspaceId(UUID workspaceId);

    Page<ScimUser> findByWorkspaceId(UUID workspaceId, Pageable pageable);

    Page<ScimUser> findByWorkspaceIdAndUserNameContainingIgnoreCase(UUID workspaceId, String userName, Pageable pageable);

    long countByWorkspaceId(UUID workspaceId);

    @Query("SELECT u.id FROM ScimUser u WHERE u.workspace.id = :workspaceId")
    List<UUID> findIdsByWorkspaceId(@Param("workspaceId") UUID workspaceId);

    @Modifying
    @Query("DELETE FROM ScimUser u WHERE u.workspace.id = :workspaceId")
    int deleteAllByWorkspaceId(@Param("workspaceId") UUID workspaceId);
}
