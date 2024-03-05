package org.goobi.api.rest.model;

import java.util.Map;

import lombok.Data;
@Data
public class AccessLocation {
	String type;
	Map<String, String> provider;
	String bucket;
	String path;
	String url;
}
