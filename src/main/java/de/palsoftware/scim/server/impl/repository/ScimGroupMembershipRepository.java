package de.palsoftware.scim.server.impl.repository;

import de.palsoftware.scim.server.impl.model.ScimGroupMembership;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface ScimGroupMembershipRepository extends JpaRepository<ScimGroupMembership, UUID> {

    @Query("SELECT m FROM ScimGroupMembership m JOIN FETCH m.group g WHERE m.memberValue = :memberValue AND g.workspace.id = :workspaceId")
    List<ScimGroupMembership> findByMemberValueAndWorkspaceId(
            @Param("memberValue") UUID memberValue,
            @Param("workspaceId") UUID workspaceId);

    @Query("SELECT m FROM ScimGroupMembership m JOIN FETCH m.group g WHERE m.memberValue IN :memberValues AND g.workspace.id = :workspaceId")
    List<ScimGroupMembership> findByMemberValueInAndWorkspaceId(
            @Param("memberValues") List<UUID> memberValues,
            @Param("workspaceId") UUID workspaceId);

    @Modifying
    @Query("DELETE FROM ScimGroupMembership m WHERE m.memberValue = :memberValue AND m.group.id IN (SELECT g.id FROM ScimGroup g WHERE g.workspace.id = :workspaceId)")
    long deleteByMemberValueAndWorkspaceId(
            @Param("memberValue") UUID memberValue,
            @Param("workspaceId") UUID workspaceId);

    @Modifying
    @Query("DELETE FROM ScimGroupMembership m WHERE m.memberValue IN :memberValues AND m.group.id IN (SELECT g.id FROM ScimGroup g WHERE g.workspace.id = :workspaceId)")
    long deleteByMemberValueInAndWorkspaceId(
            @Param("memberValues") List<UUID> memberValues,
            @Param("workspaceId") UUID workspaceId);

    @Modifying
    @Query("DELETE FROM ScimGroupMembership m WHERE m.group.id = :groupId AND m.group.id IN (SELECT g.id FROM ScimGroup g WHERE g.workspace.id = :workspaceId)")
    long deleteByGroupIdAndWorkspaceId(
            @Param("groupId") UUID groupId,
            @Param("workspaceId") UUID workspaceId);

    @Modifying
    @Query("DELETE FROM ScimGroupMembership m WHERE m.group.id IN :groupIds AND m.group.id IN (SELECT g.id FROM ScimGroup g WHERE g.workspace.id = :workspaceId)")
    long deleteByGroupIdInAndWorkspaceId(
            @Param("groupIds") List<UUID> groupIds,
            @Param("workspaceId") UUID workspaceId);
}
