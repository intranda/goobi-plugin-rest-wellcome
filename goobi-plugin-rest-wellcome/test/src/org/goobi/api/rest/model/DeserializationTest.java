package org.goobi.api.rest.model;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

public class DeserializationTest {

    @Test
    public void testDeserialization() throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        try (InputStream in = Files.newInputStream(Paths.get("resources/pretty_resp.json"))) {
            mapper.readValue(in, ArchiveCallbackRequest.class);
        }
    }
}
