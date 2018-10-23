package org.goobi.api.rest.model;

import java.util.Date;

import lombok.Data;

@Data
public class ArchiveEvent {
    private String description;
    private Date createdDate;
    private String type;
}
