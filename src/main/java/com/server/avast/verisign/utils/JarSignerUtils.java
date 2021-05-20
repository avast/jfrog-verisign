package com.server.avast.verisign.utils;

import com.server.avast.verisign.config.properties.KeystoreProperties;
import com.server.avast.verisign.jarsigner.Main;
import com.server.avast.verisign.jarsigner.VerifyResult;
import org.artifactory.resource.ResourceStreamHandle;

import java.io.File;
import java.io.IOException;

/**
 * @author Vitasek L.
 */
public class JarSignerUtils {

    private JarSignerUtils() {
    }

    public static VerifyResult verify(ResourceStreamHandle resourceStreamHandle, KeystoreProperties keystoreProperties) throws IOException {
        return ResourceHandleUtils.createTempFile(resourceStreamHandle, file -> {
            return verify(file, keystoreProperties);
        });
    }

    public static VerifyResult verify(File jarFile, KeystoreProperties keystoreProperties) {
        final Main main = new Main();
        main.init(keystoreProperties);
        return main.verifyJar(jarFile);
    }

}
