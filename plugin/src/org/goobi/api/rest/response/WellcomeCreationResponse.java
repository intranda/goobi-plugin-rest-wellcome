package org.goobi.api.rest.response;

import javax.xml.bind.annotation.XmlRootElement;

import lombok.Data;

@XmlRootElement
public @Data class WellcomeCreationResponse {

    private String result; // success, error

    private String errorText;

    private String processName;

    private int processId;
}
