package org.goobi.api.rest.model;

import lombok.Data;

@Data
public class Version {
	String type;
	String id;
	String version;
	String createdDate;
	boolean latest;

}
