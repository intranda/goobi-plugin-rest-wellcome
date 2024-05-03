package org.goobi.api.rest.model;

import java.util.Map;

import lombok.Data;

@Data
public class SourceLocation {
    private String type;
    private Map<String, String> provider;
    private String bucket;
    private String path;
}
