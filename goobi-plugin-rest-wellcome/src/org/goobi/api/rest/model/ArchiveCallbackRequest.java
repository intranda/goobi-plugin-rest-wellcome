package org.goobi.api.rest.model;

import java.util.Date;
import java.util.List;
import java.util.Map;

import lombok.Data;

@Data
public class ArchiveCallbackRequest {
    private String id;
    private String type;
    private String uploadUrl;
    private String callbackUrl;
    private Map<String, String> ingestType;
    private Map<String, String> status;
    private Date createdDate;
    private Date lastModifiedDate;
    private List<ArchiveEvent> events;
}
