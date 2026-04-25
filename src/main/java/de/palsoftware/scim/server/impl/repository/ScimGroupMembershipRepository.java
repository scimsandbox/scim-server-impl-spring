package de.palsoftware.scim.server.impl.repository;

import de.palsoftware.scim.server.impl.model.ScimGroupMembership;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface ScimGroupMembershipRepository extends JpaRepository<ScimGroupMembership, UUID> {

    @Query("SELECT m FROM ScimGroupMembership m JOIN FETCH m.group WHERE m.memberValue = :memberValue")
    List<ScimGroupMembership> findByMemberValue(@Param("memberValue") UUID memberValue);

    @Query("SELECT m FROM ScimGroupMembership m JOIN FETCH m.group WHERE m.memberValue IN :memberValues")
    List<ScimGroupMembership> findByMemberValueIn(@Param("memberValues") List<UUID> memberValues);

    @Modifying
    @Query("delete from ScimGroupMembership membership where membership.memberValue = :memberValue")
    long deleteByMemberValue(@Param("memberValue") UUID memberValue);

    @Modifying
    @Query("delete from ScimGroupMembership membership where membership.memberValue in :memberValues")
    long deleteByMemberValueIn(@Param("memberValues") List<UUID> memberValues);

    @Modifying
    @Query("delete from ScimGroupMembership membership where membership.group.id = :groupId")
    long deleteByGroupId(@Param("groupId") UUID groupId);

    @Modifying
    @Query("delete from ScimGroupMembership membership where membership.group.id in :groupIds")
    long deleteByGroupIdIn(@Param("groupIds") List<UUID> groupIds);
}
