package de.palsoftware.scim.server.impl.model;

import java.util.Objects;

public class ScimUserAddress {

    private String formatted;

    private String streetAddress;

    private String locality;

    private String region;

    private String postalCode;

    private String country;

    private String type;

    private boolean primaryFlag = false;

    // Getters and Setters

    public String getFormatted() {
        return formatted;
    }

    public void setFormatted(String formatted) {
        this.formatted = formatted;
    }

    public String getStreetAddress() {
        return streetAddress;
    }

    public void setStreetAddress(String streetAddress) {
        this.streetAddress = streetAddress;
    }

    public String getLocality() {
        return locality;
    }

    public void setLocality(String locality) {
        this.locality = locality;
    }

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public String getPostalCode() {
        return postalCode;
    }

    public void setPostalCode(String postalCode) {
        this.postalCode = postalCode;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public boolean isPrimaryFlag() {
        return primaryFlag;
    }

    public void setPrimaryFlag(boolean primaryFlag) {
        this.primaryFlag = primaryFlag;
    }

    public ScimUserAddress copy() {
        ScimUserAddress copy = new ScimUserAddress();
        copy.setFormatted(this.formatted);
        copy.setStreetAddress(this.streetAddress);
        copy.setLocality(this.locality);
        copy.setRegion(this.region);
        copy.setPostalCode(this.postalCode);
        copy.setCountry(this.country);
        copy.setType(this.type);
        copy.setPrimaryFlag(this.primaryFlag);
        return copy;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ScimUserAddress that = (ScimUserAddress) o;
        return primaryFlag == that.primaryFlag &&
                Objects.equals(formatted, that.formatted) &&
                Objects.equals(streetAddress, that.streetAddress) &&
                Objects.equals(locality, that.locality) &&
                Objects.equals(region, that.region) &&
                Objects.equals(postalCode, that.postalCode) &&
                Objects.equals(country, that.country) &&
                Objects.equals(type, that.type);
    }

    @Override
    public int hashCode() {
        return Objects.hash(formatted, streetAddress, locality, region, postalCode, country, type, primaryFlag);
    }
}
