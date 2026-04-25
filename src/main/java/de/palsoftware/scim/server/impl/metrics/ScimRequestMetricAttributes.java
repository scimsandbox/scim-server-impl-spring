package de.palsoftware.scim.server.impl.metrics;

public final class ScimRequestMetricAttributes {

    public static final String AUTHENTICATION = ScimRequestMetricAttributes.class.getName() + ".authentication";
    public static final String THROTTLED = ScimRequestMetricAttributes.class.getName() + ".throttled";

    public static final String AUTH_OK = "ok";
    public static final String AUTH_FAILED = "failed";
    public static final String AUTH_UNKNOWN = "unknown";

    public static final String THROTTLED_YES = "yes";
    public static final String THROTTLED_NO = "no";

    private ScimRequestMetricAttributes() {
    }
}