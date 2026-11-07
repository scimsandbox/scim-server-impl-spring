package de.palsoftware.scim.server.impl.entity;

import de.palsoftware.scim.server.impl.model.Workspace;
import jakarta.persistence.*;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/**
 * JPA entity representing an RFC 9967 asynchronous operation event.
 */
@Entity
@Table(name = "scim_async_events", indexes = {
    @Index(name = "idx_scim_async_events_workspace_created_at", columnList = "workspace_id, created_at DESC")
})
public class ScimAsyncEvent {

    @Id
    @Column(name = "txn_id", nullable = false)
    private UUID txnId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "workspace_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    private Workspace workspace;

    @Column(name = "operation", length = 32, nullable = false)
    private String operation;

    @Column(name = "resource_type", length = 32, nullable = false)
    private String resourceType;

    @Column(name = "resource_id")
    private UUID resourceId;

    @Column(name = "status", length = 32, nullable = false)
    private String status;

    @Column(name = "set_payload", columnDefinition = "TEXT")
    private String setPayload;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    public ScimAsyncEvent() {}

    @PrePersist
    protected void onCreate() {
        createdAt = (createdAt == null ? Instant.now() : createdAt).truncatedTo(ChronoUnit.MICROS);
    }

    public UUID getTxnId() {
        return txnId;
    }

    public void setTxnId(UUID txnId) {
        this.txnId = txnId;
    }

    public Workspace getWorkspace() {
        return workspace;
    }

    public void setWorkspace(Workspace workspace) {
        this.workspace = workspace;
    }

    public String getOperation() {
        return operation;
    }

    public void setOperation(String operation) {
        this.operation = operation;
    }

    public String getResourceType() {
        return resourceType;
    }

    public void setResourceType(String resourceType) {
        this.resourceType = resourceType;
    }

    public UUID getResourceId() {
        return resourceId;
    }

    public void setResourceId(UUID resourceId) {
        this.resourceId = resourceId;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getSetPayload() {
        return setPayload;
    }

    public void setSetPayload(String setPayload) {
        this.setPayload = setPayload;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt != null ? createdAt.truncatedTo(ChronoUnit.MICROS) : null;
    }

    public Instant getCompletedAt() {
        return completedAt;
    }

    public void setCompletedAt(Instant completedAt) {
        this.completedAt = completedAt != null ? completedAt.truncatedTo(ChronoUnit.MICROS) : null;
    }
}
