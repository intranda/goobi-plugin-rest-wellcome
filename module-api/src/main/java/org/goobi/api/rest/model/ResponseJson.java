package org.goobi.api.rest.model;

import java.util.List;
import java.util.Map;

import lombok.Data;

@Data
public class ResponseJson {
	String context;
	String type;
	String id;
	Map<String, String> space;
	Map<String, String> info;
	Manifest manifest;
	Manifest tagManifest;
	List<AccessLocation> locations;
	String createdDate;
	String version;
	List<Version> versions;
}
