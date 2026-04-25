package de.palsoftware.scim.server.impl.scim.mapper;

import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.model.ScimGroupMembership;

import java.util.*;

/**
 * Converts between ScimGroup entity and SCIM JSON Map representation.
 */
public class ScimGroupMapper {

    private ScimGroupMapper() {
    }

    public static final String GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group";
    private static final List<String> GROUP_SCHEMAS = List.of(GROUP_SCHEMA);

    public static Map<String, Object> toScimResponse(ScimGroup group, String baseUrl) {
        Map<String, Object> result = new LinkedHashMap<>(8);
        result.put("schemas", GROUP_SCHEMAS);
        result.put("id", group.getId().toString());

        if (group.getExternalId() != null) {
            result.put("externalId", group.getExternalId());
        }

        result.put("displayName", group.getDisplayName());

        // Members
        List<ScimGroupMembership> memberList = group.getMembers();
        if (memberList != null && !memberList.isEmpty()) {
            List<Map<String, Object>> members = new ArrayList<>(memberList.size());
            for (ScimGroupMembership m : memberList) {
                members.add(memberToMap(m, baseUrl));
            }
            result.put("members", members);
        }

        // Meta
        Map<String, Object> meta = new LinkedHashMap<>(6);
        meta.put("resourceType", "Group");
        meta.put("created", group.getCreatedAt().toString());
        meta.put("lastModified", group.getLastModified().toString());
        meta.put("location", baseUrl + "/Groups/" + group.getId());
        meta.put("version", "W/\"" + group.getVersion() + "\"");
        result.put("meta", meta);

        return result;
    }

    private static Map<String, Object> memberToMap(ScimGroupMembership m, String baseUrl) {
        Map<String, Object> map = new LinkedHashMap<>(5);
        map.put("value", m.getMemberValue().toString());

        String type = m.getMemberType() != null ? m.getMemberType() : "User";
        String resourcePath = "User".equalsIgnoreCase(type) ? "/Users/" : "/Groups/";
        map.put("$ref", baseUrl + resourcePath + m.getMemberValue());
        if (m.getDisplay() != null) map.put("display", m.getDisplay());
        map.put("type", type);
        return map;
    }
}
