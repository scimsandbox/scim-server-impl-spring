package de.palsoftware.scim.server.impl.scim.mapper;

import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.validation.ScimCanonicalizer;
import de.palsoftware.scim.server.impl.scim.validation.ScimCertificateValidator;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.model.ScimUserAddress;
import de.palsoftware.scim.server.impl.model.ScimUserEmail;
import de.palsoftware.scim.server.impl.model.ScimUserEntitlement;
import de.palsoftware.scim.server.impl.model.ScimUserIm;
import de.palsoftware.scim.server.impl.model.ScimUserPhoneNumber;
import de.palsoftware.scim.server.impl.model.ScimUserPhoto;
import de.palsoftware.scim.server.impl.model.ScimUserRole;
import de.palsoftware.scim.server.impl.model.ScimUserX509Certificate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Converts between JPA entities and SCIM JSON Maps.
 * All SCIM responses are built as Map<String,Object> for maximum flexibility.
 */
public class ScimUserMapper {

    public static final int MAX_BCRYPT_PASSWORD_BYTES = 72;
    private static final BCryptPasswordEncoder PASSWORD_ENCODER = new BCryptPasswordEncoder();

    private ScimUserMapper() {
    }

    public static final String USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
    public static final String ENTERPRISE_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    private static final String VALUE_OTHER = "other";

    private static final List<String> SCHEMAS_CORE = List.of(USER_SCHEMA);
    private static final List<String> SCHEMAS_ENTERPRISE = List.of(USER_SCHEMA, ENTERPRISE_SCHEMA);

    private static final Set<String> EMAIL_TYPES = Set.of("work", "home", VALUE_OTHER);
    private static final Set<String> PHONE_TYPES = Set.of("work", "home", "mobile", "fax", "pager", VALUE_OTHER);
    private static final Set<String> IM_TYPES = Set.of("aim", "gtalk", "icq", "xmpp", "skype", "qq", "msn", "yahoo", VALUE_OTHER);
    private static final Set<String> PHOTO_TYPES = Set.of("photo", "thumbnail");
    private static final Set<String> ADDRESS_TYPES = Set.of("work", "home", VALUE_OTHER);
    private static final Set<String> ISO_ALPHA2_COUNTRIES = Set.of(Locale.getISOCountries());
    private static final Map<String, String> ISO_ALPHA3_TO_ALPHA2;

    static {
        Map<String, String> map = new HashMap<>();
        for (String alpha2 : ISO_ALPHA2_COUNTRIES) {
            try {
                String alpha3 = Locale.of("", alpha2).getISO3Country();
                if (alpha3 != null && !alpha3.isEmpty()) {
                    map.put(alpha3.toUpperCase(Locale.ROOT), alpha2);
                }
            } catch (MissingResourceException ignored) {
                // Skip countries without an ISO alpha-3 equivalent
            }
        }
        ISO_ALPHA3_TO_ALPHA2 = Collections.unmodifiableMap(map);
    }

    // Common SCIM attribute keys
    private static final String KEY_SCHEMAS = "schemas";
    private static final String KEY_EXTERNAL_ID = "externalId";
    private static final String KEY_USER_NAME = "userName";
    private static final String KEY_DISPLAY_NAME = "displayName";
    private static final String KEY_NICK_NAME = "nickName";
    private static final String KEY_PROFILE_URL = "profileUrl";
    private static final String KEY_TITLE = "title";
    private static final String KEY_USER_TYPE = "userType";
    private static final String KEY_PREFERRED_LANGUAGE = "preferredLanguage";
    private static final String KEY_LOCALE = "locale";
    private static final String KEY_TIMEZONE = "timezone";
    private static final String KEY_ACTIVE = "active";
    private static final String KEY_EMAILS = "emails";
    private static final String KEY_PHONE_NUMBERS = "phoneNumbers";
    private static final String KEY_PHOTOS = "photos";
    private static final String KEY_ADDRESSES = "addresses";
    private static final String KEY_ENTITLEMENTS = "entitlements";
    private static final String KEY_ROLES = "roles";
    private static final String KEY_X509_CERTIFICATES = "x509Certificates";
    private static final String KEY_MANAGER = "manager";
    private static final String KEY_VALUE = "value";
    private static final String KEY_TYPE = "type";
    private static final String KEY_PRIMARY = "primary";
    private static final String KEY_DISPLAY = "display";
    private static final String KEY_FORMATTED = "formatted";

    /**
     * Convert ScimUser entity to SCIM JSON response map.
     */
    public static Map<String, Object> toScimResponse(ScimUser user, String baseUrl,
                                                       List<Map<String, Object>> groups) {
        boolean hasEnterprise = hasEnterpriseData(user);
        Map<String, Object> result = new LinkedHashMap<>(hasEnterprise ? 20 : 16);

        addSchemasAndIdentifiers(user, result, hasEnterprise);
        addCoreAttributes(user, result);
        addMultiValuedAttributes(user, result);
        addComputedGroups(result, groups);
        if (hasEnterprise) {
            addEnterpriseExtension(user, baseUrl, result);
        }
        addMeta(user, baseUrl, result);

        return result;
    }

    private static void addSchemasAndIdentifiers(ScimUser user, Map<String, Object> result,
                                                  boolean hasEnterprise) {
        result.put(KEY_SCHEMAS, hasEnterprise ? SCHEMAS_ENTERPRISE : SCHEMAS_CORE);
        result.put("id", user.getId().toString());
        if (user.getExternalId() != null) {
            result.put(KEY_EXTERNAL_ID, user.getExternalId());
        }
        result.put(KEY_USER_NAME, user.getUserName());
    }

    private static void addCoreAttributes(ScimUser user, Map<String, Object> result) {
        Map<String, Object> name = buildNameMap(user);
        if (!name.isEmpty()) {
            result.put("name", name);
        }

        putIfNotNull(result, KEY_DISPLAY_NAME, user.getDisplayName());
        putIfNotNull(result, KEY_NICK_NAME, user.getNickName());
        putIfNotNull(result, KEY_PROFILE_URL, user.getProfileUrl());
        putIfNotNull(result, KEY_TITLE, user.getTitle());
        putIfNotNull(result, KEY_USER_TYPE, user.getUserType());
        putIfNotNull(result, KEY_PREFERRED_LANGUAGE, user.getPreferredLanguage());
        putIfNotNull(result, KEY_LOCALE, user.getLocale());
        putIfNotNull(result, KEY_TIMEZONE, user.getTimezone());
        result.put(KEY_ACTIVE, user.isActive());
    }

    private static void addMultiValuedAttributes(ScimUser user, Map<String, Object> result) {
        putCollection(result, KEY_EMAILS, user.getEmails(), ScimUserMapper::emailToMap);
        putCollection(result, KEY_PHONE_NUMBERS, user.getPhoneNumbers(), ScimUserMapper::phoneToMap);
        putCollection(result, "ims", user.getIms(), ScimUserMapper::imToMap);
        putCollection(result, KEY_PHOTOS, user.getPhotos(), ScimUserMapper::photoToMap);
        putCollection(result, KEY_ADDRESSES, user.getAddresses(), ScimUserMapper::addressToMap);
        putCollection(result, KEY_ENTITLEMENTS, user.getEntitlements(), ScimUserMapper::entitlementToMap);
        putCollection(result, KEY_ROLES, user.getRoles(), ScimUserMapper::roleToMap);
        putCollection(result, KEY_X509_CERTIFICATES, user.getX509Certificates(), ScimUserMapper::certToMap);
    }

    private static void addComputedGroups(Map<String, Object> result, List<Map<String, Object>> groups) {
        if (groups != null && !groups.isEmpty()) {
            result.put("groups", groups);
        }
    }

    private static void addEnterpriseExtension(ScimUser user, String baseUrl, Map<String, Object> result) {
        Map<String, Object> enterprise = new LinkedHashMap<>(8);
        putIfNotNull(enterprise, "employeeNumber", user.getEnterpriseEmployeeNumber());
        putIfNotNull(enterprise, "costCenter", user.getEnterpriseCostCenter());
        putIfNotNull(enterprise, "organization", user.getEnterpriseOrganization());
        putIfNotNull(enterprise, "division", user.getEnterpriseDivision());
        putIfNotNull(enterprise, "department", user.getEnterpriseDepartment());

        Map<String, Object> manager = buildManagerMap(user, baseUrl);
        if (!manager.isEmpty()) {
            enterprise.put(KEY_MANAGER, manager);
        }

        result.put(ENTERPRISE_SCHEMA, enterprise);
    }

    private static void addMeta(ScimUser user, String baseUrl, Map<String, Object> result) {
        Map<String, Object> meta = new LinkedHashMap<>(6);
        meta.put("resourceType", "User");
        meta.put("created", user.getCreatedAt().toString());
        String lastModified = (user.getVersion() == null || user.getVersion() == 0)
                ? user.getCreatedAt().toString()
                : user.getLastModified().toString();
        meta.put("lastModified", lastModified);
        meta.put("location", baseUrl + "/Users/" + user.getId());
        meta.put("version", "W/\"" + (user.getVersion() != null ? user.getVersion() : 0) + "\"");
        result.put("meta", meta);
    }

    /**
     * Apply SCIM JSON input to a ScimUser entity (for CREATE and PUT).
     */
    public static void applyFromScimInput(ScimUser user, Map<String, Object> input) {
        applySimpleAttributes(user, input);
        if (input.containsKey("name")) {
            applyNameAttribute(user, input.get("name"));
        }
        replaceCollection(user.getEmails(), input, KEY_EMAILS, ScimUserMapper::buildEmail);
        replaceCollection(user.getPhoneNumbers(), input, KEY_PHONE_NUMBERS, ScimUserMapper::buildPhone);
        replaceCollection(user.getAddresses(), input, KEY_ADDRESSES, ScimUserMapper::buildAddress);
        replaceCollection(user.getIms(), input, "ims", ScimUserMapper::buildIm);
        replaceCollection(user.getPhotos(), input, KEY_PHOTOS, ScimUserMapper::buildPhoto);
        replaceCollection(user.getEntitlements(), input, KEY_ENTITLEMENTS, ScimUserMapper::buildEntitlement);
        replaceCollection(user.getRoles(), input, KEY_ROLES, ScimUserMapper::buildRole);
        replaceCollection(user.getX509Certificates(), input, KEY_X509_CERTIFICATES, ScimUserMapper::buildCertificate);
        applyEnterpriseExtension(user, input);
    }

    /**
     * Clear all mutable attributes for PUT (full replacement).
     */
    public static void clearMutableAttributes(ScimUser user) {
        user.setExternalId(null);
        user.setNameFormatted(null);
        user.setNameFamilyName(null);
        user.setNameGivenName(null);
        user.setNameMiddleName(null);
        user.setNameHonorificPrefix(null);
        user.setNameHonorificSuffix(null);
        user.setDisplayName(null);
        user.setNickName(null);
        user.setProfileUrl(null);
        user.setTitle(null);
        user.setUserType(null);
        user.setPreferredLanguage(null);
        user.setLocale(null);
        user.setTimezone(null);
        user.setActive(true);
        user.setPassword(null);
        user.getEmails().clear();
        user.getPhoneNumbers().clear();
        user.getAddresses().clear();
        user.getIms().clear();
        user.getPhotos().clear();
        user.getEntitlements().clear();
        user.getRoles().clear();
        user.getX509Certificates().clear();
        user.setEnterpriseEmployeeNumber(null);
        user.setEnterpriseCostCenter(null);
        user.setEnterpriseOrganization(null);
        user.setEnterpriseDivision(null);
        user.setEnterpriseDepartment(null);
        user.setEnterpriseManagerValue(null);
        user.setEnterpriseManagerRef(null);
        user.setEnterpriseManagerDisplay(null);
    }

    // ── Helper methods ─────────────────────────────────────────

    private static boolean hasEnterpriseData(ScimUser user) {
        return user.getEnterpriseEmployeeNumber() != null ||
               user.getEnterpriseCostCenter() != null ||
               user.getEnterpriseOrganization() != null ||
               user.getEnterpriseDivision() != null ||
               user.getEnterpriseDepartment() != null ||
               user.getEnterpriseManagerValue() != null;
    }

    private static Map<String, Object> buildNameMap(ScimUser user) {
        Map<String, Object> name = new LinkedHashMap<>(8);
        if (user.getNameFormatted() != null) name.put(KEY_FORMATTED, user.getNameFormatted());
        if (user.getNameFamilyName() != null) name.put("familyName", user.getNameFamilyName());
        if (user.getNameGivenName() != null) name.put("givenName", user.getNameGivenName());
        if (user.getNameMiddleName() != null) name.put("middleName", user.getNameMiddleName());
        if (user.getNameHonorificPrefix() != null) name.put("honorificPrefix", user.getNameHonorificPrefix());
        if (user.getNameHonorificSuffix() != null) name.put("honorificSuffix", user.getNameHonorificSuffix());
        return name;
    }

    private static Map<String, Object> buildManagerMap(ScimUser user, String baseUrl) {
        Map<String, Object> manager = new LinkedHashMap<>(4);
        String mgrVal = user.getEnterpriseManagerValue();
        putIfNotNull(manager, KEY_VALUE, mgrVal);
        String rawRef = user.getEnterpriseManagerRef();
        if (mgrVal != null && !mgrVal.isBlank() && baseUrl != null && !baseUrl.isBlank()
                && (rawRef == null || rawRef.isBlank() || ScimCanonicalizer.extractCanonicalScimResourceTail(rawRef) != null)) {
            manager.put("$ref", baseUrl + "/Users/" + mgrVal);
        } else {
            putIfNotNull(manager, "$ref", rawRef);
        }
        putIfNotNull(manager, KEY_DISPLAY_NAME, user.getEnterpriseManagerDisplay());
        return manager;
    }

    private static void putIfNotNull(Map<String, Object> target, String key, Object value) {
        if (value != null) {
            target.put(key, value);
        }
    }

    private static <T> void putCollection(Map<String, Object> target, String key, List<T> values,
                                          java.util.function.Function<T, Map<String, Object>> mapper) {
        if (values != null && !values.isEmpty()) {
            List<Map<String, Object>> list = new ArrayList<>(values.size());
            for (T v : values) {
                list.add(mapper.apply(v));
            }
            target.put(key, list);
        }
    }

    private static void applySimpleAttributes(ScimUser user, Map<String, Object> input) {
        if (input.containsKey(KEY_USER_NAME)) user.setUserName(ScimCanonicalizer.requireNullableString(input.get(KEY_USER_NAME), KEY_USER_NAME));
        if (input.containsKey(KEY_EXTERNAL_ID)) user.setExternalId(ScimCanonicalizer.requireNullableString(input.get(KEY_EXTERNAL_ID), KEY_EXTERNAL_ID));
        if (input.containsKey(KEY_DISPLAY_NAME)) user.setDisplayName(ScimCanonicalizer.requireNullableString(input.get(KEY_DISPLAY_NAME), KEY_DISPLAY_NAME));
        if (input.containsKey(KEY_NICK_NAME)) user.setNickName(ScimCanonicalizer.requireNullableString(input.get(KEY_NICK_NAME), KEY_NICK_NAME));
        if (input.containsKey(KEY_PROFILE_URL)) user.setProfileUrl(ScimCanonicalizer.requireNullableString(input.get(KEY_PROFILE_URL), KEY_PROFILE_URL));
        if (input.containsKey(KEY_TITLE)) user.setTitle(ScimCanonicalizer.requireNullableString(input.get(KEY_TITLE), KEY_TITLE));
        if (input.containsKey(KEY_USER_TYPE)) user.setUserType(ScimCanonicalizer.requireNullableString(input.get(KEY_USER_TYPE), KEY_USER_TYPE));
        if (input.containsKey(KEY_PREFERRED_LANGUAGE)) user.setPreferredLanguage(ScimCanonicalizer.requireNullableString(input.get(KEY_PREFERRED_LANGUAGE), KEY_PREFERRED_LANGUAGE));
        if (input.containsKey(KEY_LOCALE)) user.setLocale(ScimCanonicalizer.requireNullableString(input.get(KEY_LOCALE), KEY_LOCALE));
        if (input.containsKey(KEY_TIMEZONE)) user.setTimezone(ScimCanonicalizer.requireNullableString(input.get(KEY_TIMEZONE), KEY_TIMEZONE));
        if (input.containsKey(KEY_ACTIVE)) user.setActive(ScimCanonicalizer.requireBoolean(input.get(KEY_ACTIVE), KEY_ACTIVE, true));
        if (input.containsKey("password")) {
            String pw = ScimCanonicalizer.requireNullableString(input.get("password"), "password");
            user.setPassword(hashPassword(pw));
        }
    }

    public static String hashPassword(String password) {
        if (password == null || password.isEmpty()) {
            return password;
        }
        if (password.getBytes(StandardCharsets.UTF_8).length > MAX_BCRYPT_PASSWORD_BYTES) {
            throw new ScimException(400, "invalidValue",
                    "Password must not exceed " + MAX_BCRYPT_PASSWORD_BYTES + " UTF-8 bytes");
        }
        if (password.startsWith("$2a$") || password.startsWith("$2b$") || password.startsWith("$2y$")) {
            return password;
        }
        return PASSWORD_ENCODER.encode(password);
    }

    @SuppressWarnings("unchecked")
    private static void applyNameAttribute(ScimUser user, Object nameObj) {
        if (nameObj == null) {
            user.setNameFormatted(null);
            user.setNameFamilyName(null);
            user.setNameGivenName(null);
            user.setNameMiddleName(null);
            user.setNameHonorificPrefix(null);
            user.setNameHonorificSuffix(null);
            return;
        }
        if (!(nameObj instanceof Map<?, ?> rawNameMap)) {
            throw new ScimException(400, "invalidValue", "Attribute 'name' must be a complex object");
        }
        Map<String, Object> nameMap = (Map<String, Object>) rawNameMap;
        // Validate every sub-attribute in 'name' is scalar string (RFC 7643 §2.3.8: complex attributes MUST NOT have nested complex sub-attributes)
        for (Map.Entry<String, Object> entry : nameMap.entrySet()) {
            ScimCanonicalizer.requireNullableString(entry.getValue(), "name." + entry.getKey());
        }
        if (nameMap.containsKey(KEY_FORMATTED)) user.setNameFormatted(ScimCanonicalizer.requireNullableString(nameMap.get(KEY_FORMATTED), "name.formatted"));
        if (nameMap.containsKey("familyName")) user.setNameFamilyName(ScimCanonicalizer.requireNullableString(nameMap.get("familyName"), "name.familyName"));
        if (nameMap.containsKey("givenName")) user.setNameGivenName(ScimCanonicalizer.requireNullableString(nameMap.get("givenName"), "name.givenName"));
        if (nameMap.containsKey("middleName")) user.setNameMiddleName(ScimCanonicalizer.requireNullableString(nameMap.get("middleName"), "name.middleName"));
        if (nameMap.containsKey("honorificPrefix")) user.setNameHonorificPrefix(ScimCanonicalizer.requireNullableString(nameMap.get("honorificPrefix"), "name.honorificPrefix"));
        if (nameMap.containsKey("honorificSuffix")) user.setNameHonorificSuffix(ScimCanonicalizer.requireNullableString(nameMap.get("honorificSuffix"), "name.honorificSuffix"));
    }

    @SuppressWarnings("unchecked")
    private static <T> void replaceCollection(List<T> target, Map<String, Object> input, String key,
                                              java.util.function.Function<Map<String, Object>, T> mapper) {
        if (!input.containsKey(key)) {
            return;
        }
        target.clear();
        Object rawItems = input.get(key);
        if (rawItems == null) {
            return;
        }
        if (!(rawItems instanceof List<?> rawList)) {
            throw new ScimException(400, "invalidValue", "Attribute '" + key + "' must be an array");
        }
        List<Map<String, Object>> items = new ArrayList<>(rawList.size());
        for (Object elem : rawList) {
            if (!(elem instanceof Map<?, ?> elemMap)) {
                throw new ScimException(400, "invalidValue", "Elements of '" + key + "' must be complex objects");
            }
            items.add((Map<String, Object>) elemMap);
        }
        addAndNormalizeItems(items, target, mapper, KEY_EMAILS.equals(key));
    }

    public static <T> void addAndNormalizeItems(List<Map<String, Object>> items, List<T> target,
                                                java.util.function.Function<Map<String, Object>, T> mapper,
                                                boolean caseInsensitive) {
        for (Map<String, Object> item : items) {
            T newItem = mapper.apply(item);
            T existingDuplicate = findDuplicateItem(target, newItem, caseInsensitive);
            boolean newIsPrimary = isPrimaryItem(newItem);
            if (existingDuplicate != null) {
                if (newIsPrimary) {
                    for (T other : target) {
                        setPrimaryItem(other, false);
                    }
                    setPrimaryItem(existingDuplicate, true);
                }
            } else {
                if (newIsPrimary) {
                    for (T other : target) {
                        setPrimaryItem(other, false);
                    }
                }
                target.add(newItem);
            }
        }
    }

    public static <T> void deduplicateAndNormalizeCollection(List<T> collection, boolean caseInsensitive) {
        if (collection == null || collection.size() <= 1) {
            return;
        }
        List<T> normalized = new ArrayList<>(collection.size());
        for (T item : collection) {
            T existingDuplicate = findDuplicateItem(normalized, item, caseInsensitive);
            boolean itemIsPrimary = isPrimaryItem(item);
            if (existingDuplicate != null) {
                if (itemIsPrimary) {
                    for (T other : normalized) {
                        setPrimaryItem(other, false);
                    }
                    setPrimaryItem(existingDuplicate, true);
                }
            } else {
                if (itemIsPrimary) {
                    for (T other : normalized) {
                        setPrimaryItem(other, false);
                    }
                }
                normalized.add(item);
            }
        }
        collection.clear();
        collection.addAll(normalized);
    }

    private static <T> T findDuplicateItem(List<T> target, T candidate, boolean caseInsensitive) {
        String candidateValue = getItemValue(candidate);
        if (candidateValue == null) {
            return null;
        }
        String candidateType = getItemType(candidate);
        for (T existing : target) {
            String existingValue = getItemValue(existing);
            if (existingValue == null) {
                continue;
            }
            String existingType = getItemType(existing);
            if (caseInsensitive) {
                String normCandType = candidateType != null ? candidateType.trim() : "";
                String normExistType = existingType != null ? existingType.trim() : "";
                if (normCandType.equalsIgnoreCase(normExistType)
                        && candidateValue.trim().equalsIgnoreCase(existingValue.trim())) {
                    return existing;
                }
            } else {
                if (Objects.equals(candidateType, existingType) && Objects.equals(candidateValue, existingValue)) {
                    return existing;
                }
            }
        }
        return null;
    }

    private static String getItemValue(Object item) {
        return switch (item) {
            case ScimUserEmail e -> e.getValue();
            case ScimUserPhoneNumber p -> p.getValue();
            case ScimUserIm i -> i.getValue();
            case ScimUserPhoto ph -> ph.getValue();
            case ScimUserEntitlement ent -> ent.getValue();
            case ScimUserRole r -> r.getValue();
            case ScimUserX509Certificate c -> c.getValue();
            default -> null;
        };
    }

    private static String getItemType(Object item) {
        return switch (item) {
            case ScimUserEmail e -> e.getType();
            case ScimUserPhoneNumber p -> p.getType();
            case ScimUserAddress a -> a.getType();
            case ScimUserIm i -> i.getType();
            case ScimUserPhoto ph -> ph.getType();
            case ScimUserEntitlement ent -> ent.getType();
            case ScimUserRole r -> r.getType();
            case ScimUserX509Certificate c -> c.getType();
            default -> null;
        };
    }

    private static boolean isPrimaryItem(Object item) {
        return switch (item) {
            case ScimUserEmail e -> e.isPrimaryFlag();
            case ScimUserPhoneNumber p -> p.isPrimaryFlag();
            case ScimUserAddress a -> a.isPrimaryFlag();
            case ScimUserIm i -> i.isPrimaryFlag();
            case ScimUserPhoto ph -> ph.isPrimaryFlag();
            case ScimUserEntitlement ent -> ent.isPrimaryFlag();
            case ScimUserRole r -> r.isPrimaryFlag();
            case ScimUserX509Certificate c -> c.isPrimaryFlag();
            default -> false;
        };
    }

    private static void setPrimaryItem(Object item, boolean primary) {
        switch (item) {
            case ScimUserEmail e -> e.setPrimaryFlag(primary);
            case ScimUserPhoneNumber p -> p.setPrimaryFlag(primary);
            case ScimUserAddress a -> a.setPrimaryFlag(primary);
            case ScimUserIm i -> i.setPrimaryFlag(primary);
            case ScimUserPhoto ph -> ph.setPrimaryFlag(primary);
            case ScimUserEntitlement ent -> ent.setPrimaryFlag(primary);
            case ScimUserRole r -> r.setPrimaryFlag(primary);
            case ScimUserX509Certificate c -> c.setPrimaryFlag(primary);
            default -> {
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static void applyEnterpriseExtension(ScimUser user, Map<String, Object> input) {
        Object rawEnterprise = input.get(ENTERPRISE_SCHEMA);
        if (rawEnterprise == null) {
            for (Map.Entry<String, Object> entry : input.entrySet()) {
                if (ENTERPRISE_SCHEMA.equalsIgnoreCase(entry.getKey())) {
                    rawEnterprise = entry.getValue();
                    break;
                }
            }
        }
        if (rawEnterprise == null) {
            return;
        }
        if (!(rawEnterprise instanceof Map<?, ?> rawMap)) {
            throw new ScimException(400, "invalidValue", "Enterprise extension must be a complex object");
        }
        Map<String, Object> enterprise = (Map<String, Object>) rawMap;
        if (enterprise.containsKey("employeeNumber")) {
            user.setEnterpriseEmployeeNumber(ScimCanonicalizer.requireNullableString(enterprise.get("employeeNumber"), "employeeNumber"));
        }
        if (enterprise.containsKey("costCenter")) {
            user.setEnterpriseCostCenter(ScimCanonicalizer.requireNullableString(enterprise.get("costCenter"), "costCenter"));
        }
        if (enterprise.containsKey("organization")) {
            user.setEnterpriseOrganization(ScimCanonicalizer.requireNullableString(enterprise.get("organization"), "organization"));
        }
        if (enterprise.containsKey("division")) {
            user.setEnterpriseDivision(ScimCanonicalizer.requireNullableString(enterprise.get("division"), "division"));
        }
        if (enterprise.containsKey("department")) {
            user.setEnterpriseDepartment(ScimCanonicalizer.requireNullableString(enterprise.get("department"), "department"));
        }
        if (enterprise.containsKey(KEY_MANAGER)) {
            applyEnterpriseManager(user, enterprise.get(KEY_MANAGER));
        }
    }

    @SuppressWarnings("unchecked")
    public static void applyEnterpriseManager(ScimUser user, Object managerObj) {
        if (managerObj == null) {
            user.setEnterpriseManagerValue(null);
            user.setEnterpriseManagerRef(null);
            user.setEnterpriseManagerDisplay(null);
            return;
        }
        if (managerObj instanceof Map<?, ?> rawManager) {
            Map<String, Object> manager = (Map<String, Object>) rawManager;
            // Validate scalar types inside manager (RFC 7643 §2.3.8)
            for (Map.Entry<String, Object> entry : manager.entrySet()) {
                ScimCanonicalizer.requireNullableString(entry.getValue(), "manager." + entry.getKey());
            }
            String mgrVal = ScimCanonicalizer.requireNullableString(manager.get(KEY_VALUE), "manager.value");
            String rawRef = ScimCanonicalizer.requireNullableString(manager.get("$ref"), "manager.$ref");
            boolean hasVal = mgrVal != null && !mgrVal.isBlank();
            boolean hasRef = rawRef != null && !rawRef.isBlank();

            if (!hasVal && !hasRef) {
                user.setEnterpriseManagerValue(null);
                user.setEnterpriseManagerRef(null);
                user.setEnterpriseManagerDisplay(null);
                return;
            }

            String refUserId = null;
            String trimmedRef = null;
            if (hasRef) {
                trimmedRef = rawRef.trim();
                refUserId = extractAndValidateManagerUserIdFromRef(trimmedRef, "manager.$ref");
            }

            if (hasVal) {
                String canonicalVal = canonicalizeManagerIdentifier(ScimCanonicalizer.normalizeNfc(mgrVal.trim()));
                if (refUserId != null && !canonicalVal.startsWith("bulkId:") && !refUserId.startsWith("bulkId:")
                        && !canonicalVal.equals(refUserId)) {
                    throw new ScimException(400, "invalidValue",
                            "Attribute 'manager.$ref' does not match manager value '" + mgrVal.trim() + "'");
                }
                user.setEnterpriseManagerValue(canonicalVal);
                user.setEnterpriseManagerRef(trimmedRef);
            } else {
                user.setEnterpriseManagerValue(refUserId);
                user.setEnterpriseManagerRef(trimmedRef);
            }
            // RFC 7643 §4.3: manager.displayName is mutability="readOnly"; ignore client input and resolve server-side
            user.setEnterpriseManagerDisplay(null);
            return;
        }
        if (managerObj instanceof String managerValue) {
            String normalized = ScimCanonicalizer.normalizeNfc(managerValue.trim());
            if (normalized.isEmpty()) {
                user.setEnterpriseManagerValue(null);
                user.setEnterpriseManagerRef(null);
                user.setEnterpriseManagerDisplay(null);
            } else {
                user.setEnterpriseManagerValue(canonicalizeManagerIdentifier(normalized));
                user.setEnterpriseManagerRef(null);
                user.setEnterpriseManagerDisplay(null);
            }
            return;
        }
        throw new ScimException(400, "invalidValue", "Enterprise manager must be a complex object or string");
    }

    public static String canonicalizeManagerIdentifier(String rawId) {
        if (rawId == null) {
            return null;
        }
        String trimmed = rawId.trim();
        if (trimmed.length() == 36) {
            try {
                UUID parsed = UUID.fromString(trimmed);
                if (parsed.toString().equalsIgnoreCase(trimmed)) {
                    return parsed.toString();
                }
            } catch (IllegalArgumentException _) {
                // Keep non-UUID identifiers as-is
            }
        }
        return trimmed;
    }

    public static String extractAndValidateManagerUserIdFromRef(String rawRef, String fieldName) {
        String normalizedUri;
        try {
            normalizedUri = new java.net.URI(rawRef).normalize().toString();
        } catch (java.net.URISyntaxException e) {
            throw new ScimException(400, "invalidValue",
                    "Invalid URI reference for attribute '" + fieldName + "': " + e.getMessage(), e);
        }
        String tail = ScimCanonicalizer.extractCanonicalScimResourceTail(normalizedUri);
        if (tail == null || !tail.startsWith("Users/")) {
            throw new ScimException(400, "invalidValue",
                    "Attribute '" + fieldName + "' must reference a SCIM User URI: " + rawRef);
        }
        String userId = tail.substring("Users/".length());
        if (userId.isBlank()) {
            throw new ScimException(400, "invalidValue",
                    "Attribute '" + fieldName + "' must include a non-empty User identifier: " + rawRef);
        }
        return userId;
    }

    public static ScimUserEmail buildEmail(Map<String, Object> item) {
        validateFlatComplexElement(item, KEY_EMAILS, KEY_PRIMARY);
        ScimUserEmail email = new ScimUserEmail();
        String rawVal = ScimCanonicalizer.requireNullableString(item.get(KEY_VALUE), "emails.value");
        email.setValue(ScimCanonicalizer.canonicalizeEmail(rawVal));
        email.setType(ScimCanonicalizer.canonicalizeType(item.get(KEY_TYPE), EMAIL_TYPES, "work", "emails.type"));
        email.setDisplay(ScimCanonicalizer.requireNullableString(item.get(KEY_DISPLAY), "emails.display"));
        email.setPrimaryFlag(ScimCanonicalizer.requireBoolean(item.get(KEY_PRIMARY), "emails.primary", false));
        return email;
    }

    public static ScimUserPhoneNumber buildPhone(Map<String, Object> item) {
        validateFlatComplexElement(item, KEY_PHONE_NUMBERS, KEY_PRIMARY);
        ScimUserPhoneNumber phone = new ScimUserPhoneNumber();
        String rawVal = ScimCanonicalizer.requireNullableString(item.get(KEY_VALUE), "phoneNumbers.value");
        phone.setValue(ScimCanonicalizer.canonicalizePhoneNumber(rawVal));
        phone.setType(ScimCanonicalizer.canonicalizeType(item.get(KEY_TYPE), PHONE_TYPES, null, "phoneNumbers.type"));
        phone.setDisplay(ScimCanonicalizer.requireNullableString(item.get(KEY_DISPLAY), "phoneNumbers.display"));
        phone.setPrimaryFlag(ScimCanonicalizer.requireBoolean(item.get(KEY_PRIMARY), "phoneNumbers.primary", false));
        return phone;
    }

    public static ScimUserAddress buildAddress(Map<String, Object> item) {
        validateFlatComplexElement(item, KEY_ADDRESSES, KEY_PRIMARY);
        ScimUserAddress address = new ScimUserAddress();
        address.setFormatted(ScimCanonicalizer.requireNullableString(item.get(KEY_FORMATTED), "addresses.formatted"));
        address.setStreetAddress(ScimCanonicalizer.requireNullableString(item.get("streetAddress"), "addresses.streetAddress"));
        address.setLocality(ScimCanonicalizer.requireNullableString(item.get("locality"), "addresses.locality"));
        address.setRegion(ScimCanonicalizer.requireNullableString(item.get("region"), "addresses.region"));
        address.setPostalCode(ScimCanonicalizer.requireNullableString(item.get("postalCode"), "addresses.postalCode"));
        address.setCountry(normalizeCountry(ScimCanonicalizer.requireNullableString(item.get("country"), "addresses.country")));
        address.setType(ScimCanonicalizer.canonicalizeType(item.get(KEY_TYPE), ADDRESS_TYPES, null, "addresses.type"));
        address.setPrimaryFlag(ScimCanonicalizer.requireBoolean(item.get(KEY_PRIMARY), "addresses.primary", false));
        return address;
    }

    public static String normalizeCountry(String raw) {
        if (raw == null) return null;
        String c = raw.trim().toUpperCase(Locale.ROOT);
        if (c.isEmpty()) return null;
        if (c.length() == 2 && ISO_ALPHA2_COUNTRIES.contains(c)) {
            return c;
        }
        return ISO_ALPHA3_TO_ALPHA2.get(c);
    }

    public static ScimUserIm buildIm(Map<String, Object> item) {
        validateFlatComplexElement(item, "ims", KEY_PRIMARY);
        ScimUserIm im = new ScimUserIm();
        String rawVal = ScimCanonicalizer.requireNullableString(item.get(KEY_VALUE), "ims.value");
        im.setValue(ScimCanonicalizer.canonicalizeIm(rawVal));
        im.setType(ScimCanonicalizer.canonicalizeType(item.get(KEY_TYPE), IM_TYPES, null, "ims.type"));
        im.setDisplay(ScimCanonicalizer.requireNullableString(item.get(KEY_DISPLAY), "ims.display"));
        im.setPrimaryFlag(ScimCanonicalizer.requireBoolean(item.get(KEY_PRIMARY), "ims.primary", false));
        return im;
    }

    public static ScimUserPhoto buildPhoto(Map<String, Object> item) {
        validateFlatComplexElement(item, KEY_PHOTOS, KEY_PRIMARY);
        ScimUserPhoto photo = new ScimUserPhoto();
        photo.setValue(ScimCanonicalizer.requireNullableString(item.get(KEY_VALUE), "photos.value"));
        photo.setType(ScimCanonicalizer.canonicalizeType(item.get(KEY_TYPE), PHOTO_TYPES, null, "photos.type"));
        photo.setDisplay(ScimCanonicalizer.requireNullableString(item.get(KEY_DISPLAY), "photos.display"));
        photo.setPrimaryFlag(ScimCanonicalizer.requireBoolean(item.get(KEY_PRIMARY), "photos.primary", false));
        return photo;
    }

    public static ScimUserEntitlement buildEntitlement(Map<String, Object> item) {
        validateFlatComplexElement(item, KEY_ENTITLEMENTS, KEY_PRIMARY);
        ScimUserEntitlement entitlement = new ScimUserEntitlement();
        entitlement.setValue(ScimCanonicalizer.requireNullableString(item.get(KEY_VALUE), "entitlements.value"));
        entitlement.setType(ScimCanonicalizer.canonicalizeType(item.get(KEY_TYPE), null, null, "entitlements.type"));
        entitlement.setDisplay(ScimCanonicalizer.requireNullableString(item.get(KEY_DISPLAY), "entitlements.display"));
        entitlement.setPrimaryFlag(ScimCanonicalizer.requireBoolean(item.get(KEY_PRIMARY), "entitlements.primary", false));
        return entitlement;
    }

    public static ScimUserRole buildRole(Map<String, Object> item) {
        validateFlatComplexElement(item, KEY_ROLES, KEY_PRIMARY);
        ScimUserRole role = new ScimUserRole();
        role.setValue(ScimCanonicalizer.requireNullableString(item.get(KEY_VALUE), "roles.value"));
        role.setType(ScimCanonicalizer.canonicalizeType(item.get(KEY_TYPE), null, null, "roles.type"));
        role.setDisplay(ScimCanonicalizer.requireNullableString(item.get(KEY_DISPLAY), "roles.display"));
        role.setPrimaryFlag(ScimCanonicalizer.requireBoolean(item.get(KEY_PRIMARY), "roles.primary", false));
        return role;
    }

    public static ScimUserX509Certificate buildCertificate(Map<String, Object> item) {
        validateFlatComplexElement(item, KEY_X509_CERTIFICATES, KEY_PRIMARY);
        ScimUserX509Certificate certificate = new ScimUserX509Certificate();
        String rawVal = ScimCanonicalizer.requireNullableString(item.get(KEY_VALUE), "x509Certificates.value");
        if (rawVal != null) {
            ScimCertificateValidator.validateSingleDerCertificateOrBinary(rawVal, "x509Certificates.value");
            certificate.setValue(rawVal.trim());
        }
        certificate.setType(ScimCanonicalizer.canonicalizeType(item.get(KEY_TYPE), null, null, "x509Certificates.type"));
        certificate.setDisplay(ScimCanonicalizer.requireNullableString(item.get(KEY_DISPLAY), "x509Certificates.display"));
        certificate.setPrimaryFlag(ScimCanonicalizer.requireBoolean(item.get(KEY_PRIMARY), "x509Certificates.primary", false));
        return certificate;
    }

    private static void validateFlatComplexElement(Map<String, Object> item, String parentName, String booleanKey) {
        if (item == null) {
            throw new ScimException(400, "invalidValue", "Element of '" + parentName + "' must not be null");
        }
        for (Map.Entry<String, Object> entry : item.entrySet()) {
            Object val = entry.getValue();
            if (val instanceof Map<?, ?> || val instanceof List<?>) {
                throw new ScimException(400, "invalidValue",
                        "Complex attribute '" + parentName + "." + entry.getKey() + "' cannot contain nested complex values");
            }
            if (val != null && !entry.getKey().equalsIgnoreCase(booleanKey) && !(val instanceof String)) {
                throw new ScimException(400, "invalidValue",
                        "Attribute '" + parentName + "." + entry.getKey() + "' must be a string");
            }
        }
    }

    private static Map<String, Object> emailToMap(ScimUserEmail e) {
        Map<String, Object> m = new LinkedHashMap<>(5);
        m.put(KEY_VALUE, e.getValue());
        if (e.getType() != null) m.put(KEY_TYPE, e.getType());
        if (e.getDisplay() != null) m.put(KEY_DISPLAY, e.getDisplay());
        m.put(KEY_PRIMARY, e.isPrimaryFlag());
        return m;
    }

    private static Map<String, Object> phoneToMap(ScimUserPhoneNumber p) {
        Map<String, Object> m = new LinkedHashMap<>(5);
        m.put(KEY_VALUE, p.getValue());
        if (p.getType() != null) m.put(KEY_TYPE, p.getType());
        if (p.getDisplay() != null) m.put(KEY_DISPLAY, p.getDisplay());
        m.put(KEY_PRIMARY, p.isPrimaryFlag());
        return m;
    }

    private static Map<String, Object> imToMap(ScimUserIm i) {
        Map<String, Object> m = new LinkedHashMap<>(5);
        m.put(KEY_VALUE, i.getValue());
        if (i.getType() != null) m.put(KEY_TYPE, i.getType());
        if (i.getDisplay() != null) m.put(KEY_DISPLAY, i.getDisplay());
        m.put(KEY_PRIMARY, i.isPrimaryFlag());
        return m;
    }

    private static Map<String, Object> photoToMap(ScimUserPhoto p) {
        Map<String, Object> m = new LinkedHashMap<>(5);
        m.put(KEY_VALUE, p.getValue());
        if (p.getType() != null) m.put(KEY_TYPE, p.getType());
        if (p.getDisplay() != null) m.put(KEY_DISPLAY, p.getDisplay());
        m.put(KEY_PRIMARY, p.isPrimaryFlag());
        return m;
    }

    private static Map<String, Object> addressToMap(ScimUserAddress a) {
        Map<String, Object> m = new LinkedHashMap<>(9);
        if (a.getFormatted() != null) m.put(KEY_FORMATTED, a.getFormatted());
        if (a.getStreetAddress() != null) m.put("streetAddress", a.getStreetAddress());
        if (a.getLocality() != null) m.put("locality", a.getLocality());
        if (a.getRegion() != null) m.put("region", a.getRegion());
        if (a.getPostalCode() != null) m.put("postalCode", a.getPostalCode());
        if (a.getCountry() != null) m.put("country", a.getCountry());
        if (a.getType() != null) m.put(KEY_TYPE, a.getType());
        m.put(KEY_PRIMARY, a.isPrimaryFlag());
        return m;
    }

    private static Map<String, Object> entitlementToMap(ScimUserEntitlement e) {
        Map<String, Object> m = new LinkedHashMap<>(5);
        m.put(KEY_VALUE, e.getValue());
        if (e.getType() != null) m.put(KEY_TYPE, e.getType());
        if (e.getDisplay() != null) m.put(KEY_DISPLAY, e.getDisplay());
        m.put(KEY_PRIMARY, e.isPrimaryFlag());
        return m;
    }

    private static Map<String, Object> roleToMap(ScimUserRole r) {
        Map<String, Object> m = new LinkedHashMap<>(5);
        m.put(KEY_VALUE, r.getValue());
        if (r.getType() != null) m.put(KEY_TYPE, r.getType());
        if (r.getDisplay() != null) m.put(KEY_DISPLAY, r.getDisplay());
        m.put(KEY_PRIMARY, r.isPrimaryFlag());
        return m;
    }

    private static Map<String, Object> certToMap(ScimUserX509Certificate c) {
        Map<String, Object> m = new LinkedHashMap<>(5);
        m.put(KEY_VALUE, c.getValue());
        if (c.getType() != null) m.put(KEY_TYPE, c.getType());
        if (c.getDisplay() != null) m.put(KEY_DISPLAY, c.getDisplay());
        m.put(KEY_PRIMARY, c.isPrimaryFlag());
        return m;
    }
}
