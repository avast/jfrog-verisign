package com.server.avast.verisign.utils;

import org.apache.commons.io.FileUtils;
import org.artifactory.resource.ResourceStreamHandle;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Function;

/**
 * @author Vitasek L.
 */
public class ResourceHandleUtils {
    private ResourceHandleUtils() {
    }

    public static <T> T createTempFile(ResourceStreamHandle resourceStreamHandle, Function<File, T> consumer) throws IOException {
        Path tempFile = Files.createTempFile(null, null);
        File jarFile = tempFile.toFile();
        try (InputStream in = resourceStreamHandle.getInputStream()) {
            FileUtils.copyInputStreamToFile(in, jarFile);

            return consumer.apply(jarFile);
        } finally {
            FileUtils.deleteQuietly(jarFile);
        }
    }
}
