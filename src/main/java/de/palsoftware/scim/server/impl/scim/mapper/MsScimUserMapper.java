package de.palsoftware.scim.server.impl.scim.mapper;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * MS SCIM Validator compat layer.
 * <p>
 * Fixes two issues the validator has with standard SCIM responses:
 * <ol>
 *   <li><b>primary field</b> — the POST-verify GET uses {@code primary eq "true"}
 *       (quoted-string filter) which won't match a JSON boolean.  We convert
 *       {@code primary} from boolean to string in entitlements/roles/x509Certificates.</li>
 *   <li><b>enterprise manager</b> — the validator expects a flattened
 *       {@code urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager}
 *       top-level key.</li>
 * </ol>
 * <b>Note:</b> the PATCH test ({@code primary eq true}, unquoted boolean filter) cannot
 * be fixed via response transformation — this is a validator limitation.
 */
public final class MsScimUserMapper {

    private static final String KEY_PRIMARY = "primary";

    private static final String[] PRIMARY_COLLECTIONS = {
        "entitlements", "roles", "x509Certificates"
    };

    private static final String MANAGER_ALIAS =
            ScimUserMapper.ENTERPRISE_SCHEMA + ":manager";

    private MsScimUserMapper() {
    }

    public static Map<String, Object> toMsCompat(Map<String, Object> scim) {
        if (scim == null) {
            return Collections.emptyMap();
        }
        convertPrimaryToString(scim);
        addManagerAlias(scim);
        return scim;
    }

    /** Convert boolean {@code primary} to string {@code "true"}/{@code "false"}. */
    @SuppressWarnings("unchecked")
    private static void convertPrimaryToString(Map<String, Object> scim) {
        for (String key : PRIMARY_COLLECTIONS) {
            Object val = scim.get(key);
            if (!(val instanceof List)) continue;
            for (Object item : (List<Object>) val) {
                if (!(item instanceof Map)) continue;
                Map<String, Object> entry = (Map<String, Object>) item;
                Object p = entry.get(KEY_PRIMARY);
                if (Boolean.TRUE.equals(p))  entry.put(KEY_PRIMARY, "true");
                if (Boolean.FALSE.equals(p)) entry.put(KEY_PRIMARY, "false");
            }
        }
    }

    /** Flatten enterprise manager value to top-level colon-separated key. */
    @SuppressWarnings("unchecked")
    private static void addManagerAlias(Map<String, Object> scim) {
        Object ext = scim.get(ScimUserMapper.ENTERPRISE_SCHEMA);
        if (!(ext instanceof Map)) return;
        Object mgr = ((Map<String, Object>) ext).get("manager");
        if (mgr instanceof Map) {
            Object v = ((Map<String, Object>) mgr).get("value");
            if (v != null) scim.put(MANAGER_ALIAS, v);
        } else if (mgr != null) {
            scim.put(MANAGER_ALIAS, mgr);
        }
    }
}
