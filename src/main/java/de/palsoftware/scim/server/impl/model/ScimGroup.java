package de.palsoftware.scim.server.impl.model;

import jakarta.persistence.*;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "scim_groups", uniqueConstraints = {
    @UniqueConstraint(columnNames = {"workspace_id", "display_name"})
}, indexes = {
    @Index(name = "idx_group_external_id", columnList = "workspace_id, external_id")
})
public class ScimGroup {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "workspace_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    private Workspace workspace;

    @Column(name = "external_id")
    private String externalId;

    @Column(name = "display_name", nullable = false)
    private String displayName;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_modified", nullable = false)
    private Instant lastModified;

    @Version
    @Column(name = "version")
    private Long version;

    @OneToMany(mappedBy = "group", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @org.hibernate.annotations.BatchSize(size = 200)
    private List<ScimGroupMembership> members = new ArrayList<>();

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now().truncatedTo(ChronoUnit.MICROS);
        lastModified = createdAt;
    }

    @PreUpdate
    protected void onUpdate() {
        lastModified = Instant.now().truncatedTo(ChronoUnit.MICROS);
    }

    // Getters and Setters

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public Workspace getWorkspace() {
        return workspace;
    }

    public void setWorkspace(Workspace workspace) {
        this.workspace = workspace;
    }

    public String getExternalId() {
        return externalId;
    }

    public void setExternalId(String externalId) {
        this.externalId = externalId;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt != null ? createdAt.truncatedTo(ChronoUnit.MICROS) : null;
    }

    public Instant getLastModified() {
        return lastModified;
    }

    public void setLastModified(Instant lastModified) {
        this.lastModified = lastModified != null ? lastModified.truncatedTo(ChronoUnit.MICROS) : null;
    }

    public Long getVersion() {
        return version;
    }

    public void setVersion(Long version) {
        this.version = version;
    }

    public List<ScimGroupMembership> getMembers() {
        return members;
    }

    public void setMembers(List<ScimGroupMembership> members) {
        this.members = members;
    }
}
