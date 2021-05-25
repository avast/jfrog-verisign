package com.server.avast.verisign.config.properties;

import java.util.Arrays;
import java.util.List;

/**
 * @author Vitasek L.
 */
public class VerifyJarProperties {
    private List<String> extensions = Arrays.asList("jar", "aar");
    private boolean enabled = true;
    private KeystoreProperties keystore;

    public List<String> getExtensions() {
        return extensions;
    }

    public void setExtensions(List<String> extensions) {
        this.extensions = extensions;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public KeystoreProperties getKeystore() {
        return keystore;
    }

    public void setKeystore(KeystoreProperties keystore) {
        this.keystore = keystore;
    }
}
