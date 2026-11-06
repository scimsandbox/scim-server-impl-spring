package de.palsoftware.scim.server.impl.model;

import jakarta.persistence.*;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

@Entity
@Table(name = "scim_users", uniqueConstraints = {
    @UniqueConstraint(columnNames = {"workspace_id", "user_name"})
}, indexes = {
    @Index(name = "idx_user_external_id", columnList = "workspace_id, external_id")
})
public class ScimUser {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "workspace_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    private Workspace workspace;

    @Column(name = "user_name", nullable = false)
    private String userName;

    @Column(name = "external_id")
    private String externalId;

    // ---- Name sub-attributes (flattened) ----

    @Column(name = "name_formatted")
    private String nameFormatted;

    @Column(name = "name_family_name")
    private String nameFamilyName;

    @Column(name = "name_given_name")
    private String nameGivenName;

    @Column(name = "name_middle_name")
    private String nameMiddleName;

    @Column(name = "name_honorific_prefix")
    private String nameHonorificPrefix;

    @Column(name = "name_honorific_suffix")
    private String nameHonorificSuffix;

    // ---- Core attributes ----

    @Column(name = "display_name")
    private String displayName;

    @Column(name = "nick_name")
    private String nickName;

    @Column(name = "profile_url")
    private String profileUrl;

    private String title;

    @Column(name = "user_type")
    private String userType;

    @Column(name = "preferred_language")
    private String preferredLanguage;

    private String locale;

    private String timezone;

    @Column(nullable = false)
    private boolean active = true;

    @Column(name = "password")
    private String password;

    // ---- Enterprise Extension fields ----

    @Column(name = "enterprise_employee_number")
    private String enterpriseEmployeeNumber;

    @Column(name = "enterprise_cost_center")
    private String enterpriseCostCenter;

    @Column(name = "enterprise_organization")
    private String enterpriseOrganization;

    @Column(name = "enterprise_division")
    private String enterpriseDivision;

    @Column(name = "enterprise_department")
    private String enterpriseDepartment;

    @Column(name = "enterprise_manager_value")
    private String enterpriseManagerValue;

    @Column(name = "enterprise_manager_ref")
    private String enterpriseManagerRef;

    @Column(name = "enterprise_manager_display")
    private String enterpriseManagerDisplay;

    // ---- Meta fields ----

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_modified", nullable = false)
    private Instant lastModified;

    @Version
    @Column(name = "version")
    private Long version;

    // ---- Multi-valued collections ----

    @org.hibernate.annotations.JdbcTypeCode(org.hibernate.type.SqlTypes.JSON)
    private List<ScimUserEmail> emails = new ArrayList<>();

    @org.hibernate.annotations.JdbcTypeCode(org.hibernate.type.SqlTypes.JSON)
    private List<ScimUserPhoneNumber> phoneNumbers = new ArrayList<>();

    @org.hibernate.annotations.JdbcTypeCode(org.hibernate.type.SqlTypes.JSON)
    private List<ScimUserAddress> addresses = new ArrayList<>();

    @org.hibernate.annotations.JdbcTypeCode(org.hibernate.type.SqlTypes.JSON)
    private List<ScimUserEntitlement> entitlements = new ArrayList<>();

    @org.hibernate.annotations.JdbcTypeCode(org.hibernate.type.SqlTypes.JSON)
    private List<ScimUserRole> roles = new ArrayList<>();

    @org.hibernate.annotations.JdbcTypeCode(org.hibernate.type.SqlTypes.JSON)
    private List<ScimUserIm> ims = new ArrayList<>();

    @org.hibernate.annotations.JdbcTypeCode(org.hibernate.type.SqlTypes.JSON)
    private List<ScimUserPhoto> photos = new ArrayList<>();

    @org.hibernate.annotations.JdbcTypeCode(org.hibernate.type.SqlTypes.JSON)
    @Column(name = "x509_certificates")
    private List<ScimUserX509Certificate> x509Certificates = new ArrayList<>();

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

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getExternalId() {
        return externalId;
    }

    public void setExternalId(String externalId) {
        this.externalId = externalId;
    }

    public String getNameFormatted() {
        return nameFormatted;
    }

    public void setNameFormatted(String nameFormatted) {
        this.nameFormatted = nameFormatted;
    }

    public String getNameFamilyName() {
        return nameFamilyName;
    }

    public void setNameFamilyName(String nameFamilyName) {
        this.nameFamilyName = nameFamilyName;
    }

    public String getNameGivenName() {
        return nameGivenName;
    }

    public void setNameGivenName(String nameGivenName) {
        this.nameGivenName = nameGivenName;
    }

    public String getNameMiddleName() {
        return nameMiddleName;
    }

    public void setNameMiddleName(String nameMiddleName) {
        this.nameMiddleName = nameMiddleName;
    }

    public String getNameHonorificPrefix() {
        return nameHonorificPrefix;
    }

    public void setNameHonorificPrefix(String nameHonorificPrefix) {
        this.nameHonorificPrefix = nameHonorificPrefix;
    }

    public String getNameHonorificSuffix() {
        return nameHonorificSuffix;
    }

    public void setNameHonorificSuffix(String nameHonorificSuffix) {
        this.nameHonorificSuffix = nameHonorificSuffix;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getNickName() {
        return nickName;
    }

    public void setNickName(String nickName) {
        this.nickName = nickName;
    }

    public String getProfileUrl() {
        return profileUrl;
    }

    public void setProfileUrl(String profileUrl) {
        this.profileUrl = profileUrl;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getUserType() {
        return userType;
    }

    public void setUserType(String userType) {
        this.userType = userType;
    }

    public String getPreferredLanguage() {
        return preferredLanguage;
    }

    public void setPreferredLanguage(String preferredLanguage) {
        this.preferredLanguage = preferredLanguage;
    }

    public String getLocale() {
        return locale;
    }

    public void setLocale(String locale) {
        this.locale = locale;
    }

    public String getTimezone() {
        return timezone;
    }

    public void setTimezone(String timezone) {
        this.timezone = timezone;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEnterpriseEmployeeNumber() {
        return enterpriseEmployeeNumber;
    }

    public void setEnterpriseEmployeeNumber(String enterpriseEmployeeNumber) {
        this.enterpriseEmployeeNumber = enterpriseEmployeeNumber;
    }

    public String getEnterpriseCostCenter() {
        return enterpriseCostCenter;
    }

    public void setEnterpriseCostCenter(String enterpriseCostCenter) {
        this.enterpriseCostCenter = enterpriseCostCenter;
    }

    public String getEnterpriseOrganization() {
        return enterpriseOrganization;
    }

    public void setEnterpriseOrganization(String enterpriseOrganization) {
        this.enterpriseOrganization = enterpriseOrganization;
    }

    public String getEnterpriseDivision() {
        return enterpriseDivision;
    }

    public void setEnterpriseDivision(String enterpriseDivision) {
        this.enterpriseDivision = enterpriseDivision;
    }

    public String getEnterpriseDepartment() {
        return enterpriseDepartment;
    }

    public void setEnterpriseDepartment(String enterpriseDepartment) {
        this.enterpriseDepartment = enterpriseDepartment;
    }

    public String getEnterpriseManagerValue() {
        return enterpriseManagerValue;
    }

    public void setEnterpriseManagerValue(String enterpriseManagerValue) {
        this.enterpriseManagerValue = enterpriseManagerValue;
    }

    public String getEnterpriseManagerRef() {
        return enterpriseManagerRef;
    }

    public void setEnterpriseManagerRef(String enterpriseManagerRef) {
        this.enterpriseManagerRef = enterpriseManagerRef;
    }

    public String getEnterpriseManagerDisplay() {
        return enterpriseManagerDisplay;
    }

    public void setEnterpriseManagerDisplay(String enterpriseManagerDisplay) {
        this.enterpriseManagerDisplay = enterpriseManagerDisplay;
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

    public List<ScimUserEmail> getEmails() {
        return emails;
    }

    public void setEmails(List<ScimUserEmail> emails) {
        this.emails = emails;
    }

    public List<ScimUserPhoneNumber> getPhoneNumbers() {
        return phoneNumbers;
    }

    public void setPhoneNumbers(List<ScimUserPhoneNumber> phoneNumbers) {
        this.phoneNumbers = phoneNumbers;
    }

    public List<ScimUserAddress> getAddresses() {
        return addresses;
    }

    public void setAddresses(List<ScimUserAddress> addresses) {
        this.addresses = addresses;
    }

    public List<ScimUserEntitlement> getEntitlements() {
        return entitlements;
    }

    public void setEntitlements(List<ScimUserEntitlement> entitlements) {
        this.entitlements = entitlements;
    }

    public List<ScimUserRole> getRoles() {
        return roles;
    }

    public void setRoles(List<ScimUserRole> roles) {
        this.roles = roles;
    }

    public List<ScimUserIm> getIms() {
        return ims;
    }

    public void setIms(List<ScimUserIm> ims) {
        this.ims = ims;
    }

    public List<ScimUserPhoto> getPhotos() {
        return photos;
    }

    public void setPhotos(List<ScimUserPhoto> photos) {
        this.photos = photos;
    }

    public List<ScimUserX509Certificate> getX509Certificates() {
        return x509Certificates;
    }

    public void setX509Certificates(List<ScimUserX509Certificate> x509Certificates) {
        this.x509Certificates = x509Certificates;
    }

    private record MutableState(
            String userName,
            String externalId,
            String nameFormatted,
            String nameFamilyName,
            String nameGivenName,
            String nameMiddleName,
            String nameHonorificPrefix,
            String nameHonorificSuffix,
            String displayName,
            String nickName,
            String profileUrl,
            String title,
            String userType,
            String preferredLanguage,
            String locale,
            String timezone,
            boolean active,
            String password,
            String enterpriseEmployeeNumber,
            String enterpriseCostCenter,
            String enterpriseOrganization,
            String enterpriseDivision,
            String enterpriseDepartment,
            String enterpriseManagerValue,
            String enterpriseManagerRef,
            String enterpriseManagerDisplay,
            List<ScimUserEmail> emails,
            List<ScimUserPhoneNumber> phoneNumbers,
            List<ScimUserAddress> addresses,
            List<ScimUserEntitlement> entitlements,
            List<ScimUserRole> roles,
            List<ScimUserIm> ims,
            List<ScimUserPhoto> photos,
            List<ScimUserX509Certificate> x509Certificates
    ) {}

    private static <T> List<T> copyCollection(List<T> source, Function<T, T> copier) {
        if (source == null) {
            return new ArrayList<>();
        }
        return source.stream().map(copier).collect(Collectors.toCollection(ArrayList::new));
    }

    private MutableState toMutableState() {
        return new MutableState(
                this.userName,
                this.externalId,
                this.nameFormatted,
                this.nameFamilyName,
                this.nameGivenName,
                this.nameMiddleName,
                this.nameHonorificPrefix,
                this.nameHonorificSuffix,
                this.displayName,
                this.nickName,
                this.profileUrl,
                this.title,
                this.userType,
                this.preferredLanguage,
                this.locale,
                this.timezone,
                this.active,
                this.password,
                this.enterpriseEmployeeNumber,
                this.enterpriseCostCenter,
                this.enterpriseOrganization,
                this.enterpriseDivision,
                this.enterpriseDepartment,
                this.enterpriseManagerValue,
                this.enterpriseManagerRef,
                this.enterpriseManagerDisplay,
                copyCollection(this.emails, ScimUserEmail::copy),
                copyCollection(this.phoneNumbers, ScimUserPhoneNumber::copy),
                copyCollection(this.addresses, ScimUserAddress::copy),
                copyCollection(this.entitlements, ScimUserEntitlement::copy),
                copyCollection(this.roles, ScimUserRole::copy),
                copyCollection(this.ims, ScimUserIm::copy),
                copyCollection(this.photos, ScimUserPhoto::copy),
                copyCollection(this.x509Certificates, ScimUserX509Certificate::copy)
        );
    }

    private void applyMutableState(MutableState state) {
        this.userName = state.userName();
        this.externalId = state.externalId();
        this.nameFormatted = state.nameFormatted();
        this.nameFamilyName = state.nameFamilyName();
        this.nameGivenName = state.nameGivenName();
        this.nameMiddleName = state.nameMiddleName();
        this.nameHonorificPrefix = state.nameHonorificPrefix();
        this.nameHonorificSuffix = state.nameHonorificSuffix();
        this.displayName = state.displayName();
        this.nickName = state.nickName();
        this.profileUrl = state.profileUrl();
        this.title = state.title();
        this.userType = state.userType();
        this.preferredLanguage = state.preferredLanguage();
        this.locale = state.locale();
        this.timezone = state.timezone();
        this.active = state.active();
        this.password = state.password();
        this.enterpriseEmployeeNumber = state.enterpriseEmployeeNumber();
        this.enterpriseCostCenter = state.enterpriseCostCenter();
        this.enterpriseOrganization = state.enterpriseOrganization();
        this.enterpriseDivision = state.enterpriseDivision();
        this.enterpriseDepartment = state.enterpriseDepartment();
        this.enterpriseManagerValue = state.enterpriseManagerValue();
        this.enterpriseManagerRef = state.enterpriseManagerRef();
        this.enterpriseManagerDisplay = state.enterpriseManagerDisplay();
        this.emails = state.emails();
        this.phoneNumbers = state.phoneNumbers();
        this.addresses = state.addresses();
        this.entitlements = state.entitlements();
        this.roles = state.roles();
        this.ims = state.ims();
        this.photos = state.photos();
        this.x509Certificates = state.x509Certificates();
    }

    public void applyMutableStateFrom(ScimUser other) {
        if (other == null) {
            return;
        }
        applyMutableState(other.toMutableState());
    }

    public ScimUser copyMutableState() {
        ScimUser copy = new ScimUser();
        copy.setId(this.id);
        copy.setWorkspace(this.workspace);
        copy.setCreatedAt(this.createdAt);
        copy.setLastModified(this.lastModified);
        copy.setVersion(this.version);
        copy.applyMutableState(this.toMutableState());
        return copy;
    }

    public boolean hasSameMutableState(ScimUser other) {
        return other != null && this.toMutableState().equals(other.toMutableState());
    }
}
