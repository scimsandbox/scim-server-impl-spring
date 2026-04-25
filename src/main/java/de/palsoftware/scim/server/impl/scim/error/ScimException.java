package de.palsoftware.scim.server.impl.scim.error;

/**
 * Exception representing a SCIM protocol error per RFC 7644 §3.12.
 */
public class ScimException extends RuntimeException {

    private final int httpStatus;
    private final String scimType;

    public ScimException(int httpStatus, String scimType, String detail) {
        super(detail);
        this.httpStatus = httpStatus;
        this.scimType = scimType;
    }

    public ScimException(int httpStatus, String scimType, String detail, Throwable cause) {
        super(detail, cause);
        this.httpStatus = httpStatus;
        this.scimType = scimType;
    }

    public ScimException(int httpStatus, String detail) {
        this(httpStatus, null, detail);
    }

    public ScimException(int httpStatus, String detail, Throwable cause) {
        this(httpStatus, null, detail, cause);
    }

    public int getHttpStatus() {
        return httpStatus;
    }

    public String getScimType() {
        return scimType;
    }
}
