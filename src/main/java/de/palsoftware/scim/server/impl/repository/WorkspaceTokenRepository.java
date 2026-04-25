package de.palsoftware.scim.server.impl.repository;

import de.palsoftware.scim.server.impl.model.WorkspaceToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface WorkspaceTokenRepository extends JpaRepository<WorkspaceToken, UUID> {

    @Cacheable("workspaceTokens")
    @Query("SELECT t FROM WorkspaceToken t JOIN FETCH t.workspace WHERE t.tokenHash = :tokenHash AND t.revoked = false")
    Optional<WorkspaceToken> findByTokenHashAndNotRevoked(@Param("tokenHash") String tokenHash);

    Optional<WorkspaceToken> findByTokenHash(String tokenHash);

    List<WorkspaceToken> findByWorkspaceId(UUID workspaceId);

    @Modifying
    @Query("delete from WorkspaceToken token where token.workspace.id = :workspaceId")
    long deleteByWorkspaceId(@Param("workspaceId") UUID workspaceId);

    Optional<WorkspaceToken> findByIdAndWorkspaceId(UUID id, UUID workspaceId);

    Optional<WorkspaceToken> findByWorkspaceIdAndName(UUID workspaceId, String name);
}
