package de.palsoftware.scim.server.impl.model;

import jakarta.persistence.*;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import java.util.UUID;

@Entity
@Table(name = "scim_group_memberships", indexes = {
    @Index(name = "idx_group_memberships_workspace_group_id", columnList = "workspace_id, group_id"),
    @Index(name = "idx_group_memberships_workspace_member_value", columnList = "workspace_id, member_value"),
    @Index(name = "idx_membership_member_value", columnList = "member_value"),
    @Index(name = "idx_membership_group_id", columnList = "group_id")
})
public class ScimGroupMembership {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "group_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    private ScimGroup group;

    @Column(name = "workspace_id", nullable = false)
    private UUID workspaceId;

    @Column(name = "member_value", nullable = false)
    private UUID memberValue;

    @Column(name = "member_type", nullable = false)
    private String memberType;

    @Column(name = "display")
    private String display;

    @PrePersist
    @PreUpdate
    protected void syncWorkspaceId() {
        workspaceId = group != null && group.getWorkspace() != null ? group.getWorkspace().getId() : null;
        if (workspaceId == null) {
            throw new IllegalStateException("Group membership requires a workspace id");
        }
    }

    // Getters and Setters

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public ScimGroup getGroup() {
        return group;
    }

    public void setGroup(ScimGroup group) {
        this.group = group;
    }

    public UUID getWorkspaceId() {
        return workspaceId;
    }

    public void setWorkspaceId(UUID workspaceId) {
        this.workspaceId = workspaceId;
    }

    public UUID getMemberValue() {
        return memberValue;
    }

    public void setMemberValue(UUID memberValue) {
        this.memberValue = memberValue;
    }

    public String getMemberType() {
        return memberType;
    }

    public void setMemberType(String memberType) {
        this.memberType = memberType;
    }

    public String getDisplay() {
        return display;
    }

    public void setDisplay(String display) {
        this.display = display;
    }
}
