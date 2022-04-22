package org.goobi.api.rest.model;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.BeforeClass;
import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

//@RunWith(PowerMockRunner.class)
//@PowerMockIgnore({ "javax.management.*", "javax.net.ssl.*" ,"jdk.internal.reflect.*"})
public class DeserializationTest {

    @BeforeClass
    public static void setUpClass() throws Exception {
        String log4jFile = "test/src/log4j2.xml"; // for junit tests in eclipse
        if (!Files.exists(Paths.get(log4jFile))) {
            log4jFile = "target/test-classes/log4j2.xml"; // to run mvn test from cli or in jenkins
        }
    }

    @Test
    public void testDeserialization() throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        Path resourceFile = Paths.get("resources/pretty_resp.json");
        if (!Files.exists(resourceFile)) {
            resourceFile = Paths.get("../resources/pretty_resp.json");
        }

        try (InputStream in = Files.newInputStream(resourceFile)) {
            mapper.readValue(in, ArchiveCallbackRequest.class);
        }
    }
}
