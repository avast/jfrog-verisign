package com.server.avast.verisign.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.server.avast.verisign.config.properties.VerisignProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;

/**
 * @author Vitasek L.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Config {
    private static final Logger logger = LoggerFactory.getLogger(Config.class);
    private final ObjectMapper mapper;
    private final File propertyPath;

    private final Object lock = new Object();
    private VerisignProperties properties;

    public Config(final File propertyPath) {
        this.propertyPath = propertyPath;
        mapper = new ObjectMapper(YAMLFactory.builder().build());
        reload();
    }

    public void reload() {
        synchronized (lock) {
            try {
                logger.info("Reloading verisign config");
                properties = mapper.readValue(propertyPath, VerisignProperties.class);
                logger.info("Verisign config was reloaded successfuly");
            } catch (IOException e) {
                logger.error("Failed to load properties from file {}", propertyPath, e);
            }
        }
    }

    public VerisignProperties getProperties() {
        synchronized (lock) {
            if (properties == null) {
                reload();
            }
            return properties;
        }
    }
}
