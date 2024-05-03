package org.goobi.api.rest.model;

import java.util.List;

import lombok.Data;
@Data
public class Manifest {
	String type;
	String checksumAlgorithm;
	List<FileJson> files;

}
