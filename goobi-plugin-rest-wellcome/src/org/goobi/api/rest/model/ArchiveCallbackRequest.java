package org.goobi.api.rest.model;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class ArchiveCallbackRequest {
    private String id;
    private String type;
    private Map<String, String> ingestType;
    private Map<String, String> status;
    private List<ArchiveEvent> events;
}
