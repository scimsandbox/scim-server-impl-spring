package de.palsoftware.scim.server.impl.scim.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * SCIM 2.0 ListResponse representation per RFC 7644 §3.4.2 and RFC 9865 §2.
 * Supports both index-based pagination (startIndex) and cursor-based pagination (nextCursor, previousCursor).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScimListResponse<T> {

    public static final String SCHEMA_URI = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

    @JsonProperty("schemas")
    private List<String> schemas = List.of(SCHEMA_URI);

    @JsonProperty("totalResults")
    private long totalResults;

    @JsonProperty("startIndex")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer startIndex;

    @JsonProperty("itemsPerPage")
    private int itemsPerPage;

    @JsonProperty("Resources")
    private List<T> resources = Collections.emptyList();

    @JsonProperty("nextCursor")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String nextCursor;

    @JsonProperty("previousCursor")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String previousCursor;

    public ScimListResponse() {
    }

    public ScimListResponse(long totalResults, Integer startIndex, int itemsPerPage,
                            List<T> resources, String nextCursor, String previousCursor) {
        this.totalResults = totalResults;
        this.startIndex = startIndex;
        this.itemsPerPage = itemsPerPage;
        this.resources = resources != null ? resources : Collections.emptyList();
        this.nextCursor = nextCursor;
        this.previousCursor = previousCursor;
    }

    public static <T> ScimListResponse<T> ofIndex(List<T> resources, long totalResults, int startIndex) {
        int count = resources != null ? resources.size() : 0;
        return new ScimListResponse<>(totalResults, startIndex, count, resources, null, null);
    }

    public static <T> ScimListResponse<T> ofCursor(List<T> resources, long totalResults,
                                                   String nextCursor, String previousCursor) {
        int count = resources != null ? resources.size() : 0;
        return new ScimListResponse<>(totalResults, null, count, resources, nextCursor, previousCursor);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("schemas", schemas);
        map.put("totalResults", totalResults);
        if (startIndex != null) {
            map.put("startIndex", startIndex);
        }
        map.put("itemsPerPage", itemsPerPage);
        if (previousCursor != null) {
            map.put("previousCursor", previousCursor);
        }
        if (nextCursor != null) {
            map.put("nextCursor", nextCursor);
        }
        map.put("Resources", resources);
        return map;
    }

    public List<String> getSchemas() {
        return schemas;
    }

    public void setSchemas(List<String> schemas) {
        this.schemas = schemas;
    }

    public long getTotalResults() {
        return totalResults;
    }

    public void setTotalResults(long totalResults) {
        this.totalResults = totalResults;
    }

    public Integer getStartIndex() {
        return startIndex;
    }

    public void setStartIndex(Integer startIndex) {
        this.startIndex = startIndex;
    }

    public int getItemsPerPage() {
        return itemsPerPage;
    }

    public void setItemsPerPage(int itemsPerPage) {
        this.itemsPerPage = itemsPerPage;
    }

    public List<T> getResources() {
        return resources;
    }

    public void setResources(List<T> resources) {
        this.resources = resources;
    }

    public String getNextCursor() {
        return nextCursor;
    }

    public void setNextCursor(String nextCursor) {
        this.nextCursor = nextCursor;
    }

    public String getPreviousCursor() {
        return previousCursor;
    }

    public void setPreviousCursor(String previousCursor) {
        this.previousCursor = previousCursor;
    }
}
