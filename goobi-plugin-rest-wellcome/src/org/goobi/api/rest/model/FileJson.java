package org.goobi.api.rest.model;

import lombok.Data;

@Data
public class FileJson {
	String type;
	String name;
	String path;
	String checksum;
}
