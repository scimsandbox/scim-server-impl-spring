package de.palsoftware.scim.server.impl.scim.compat;

public enum CompatMode {
    NONE,
    MS;

    public static CompatMode fromString(String value) {
        if (value == null || value.isBlank()) {
            return NONE;
        }
        for (CompatMode mode : values()) {
            if (mode.name().equalsIgnoreCase(value)) {
                return mode;
            }
        }
        return NONE;
    }
}