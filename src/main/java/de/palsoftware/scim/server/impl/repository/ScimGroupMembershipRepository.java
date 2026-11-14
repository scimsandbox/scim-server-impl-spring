package de.palsoftware.scim.server.impl.repository;

import de.palsoftware.scim.server.impl.model.ScimGroupMembership;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface ScimGroupMembershipRepository extends JpaRepository<ScimGroupMembership, UUID> {

    @Query("SELECT m FROM ScimGroupMembership m JOIN FETCH m.group g WHERE m.workspaceId = :workspaceId AND m.memberValue = :memberValue")
    List<ScimGroupMembership> findByMemberValueAndWorkspaceId(
            @Param("memberValue") UUID memberValue,
            @Param("workspaceId") UUID workspaceId);

    @Query("SELECT m FROM ScimGroupMembership m JOIN FETCH m.group g WHERE m.workspaceId = :workspaceId AND m.memberValue IN :memberValues")
    List<ScimGroupMembership> findByMemberValueInAndWorkspaceId(
            @Param("memberValues") List<UUID> memberValues,
            @Param("workspaceId") UUID workspaceId);

    @Modifying
    @Query("DELETE FROM ScimGroupMembership m WHERE m.workspaceId = :workspaceId AND m.memberValue = :memberValue")
    long deleteByMemberValueAndWorkspaceId(
            @Param("memberValue") UUID memberValue,
            @Param("workspaceId") UUID workspaceId);
}
