package de.palsoftware.scim.server.impl.model;

import java.util.Objects;

public class ScimUserX509Certificate {

    private String value;

    private String type;

    private String display;

    private boolean primaryFlag = false;

    // Getters and Setters

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getDisplay() {
        return display;
    }

    public void setDisplay(String display) {
        this.display = display;
    }

    public boolean isPrimaryFlag() {
        return primaryFlag;
    }

    public void setPrimaryFlag(boolean primaryFlag) {
        this.primaryFlag = primaryFlag;
    }

    public ScimUserX509Certificate copy() {
        ScimUserX509Certificate copy = new ScimUserX509Certificate();
        copy.setValue(this.value);
        copy.setType(this.type);
        copy.setDisplay(this.display);
        copy.setPrimaryFlag(this.primaryFlag);
        return copy;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ScimUserX509Certificate that = (ScimUserX509Certificate) o;
        return primaryFlag == that.primaryFlag &&
                Objects.equals(value, that.value) &&
                Objects.equals(type, that.type) &&
                Objects.equals(display, that.display);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value, type, display, primaryFlag);
    }
}
