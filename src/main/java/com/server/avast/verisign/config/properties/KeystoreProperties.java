package com.server.avast.verisign.config.properties;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * @author Vitasek L.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class KeystoreProperties {
    private String keystorePath;
    private String keystorePass = "";
    private String alias;

    public KeystoreProperties() {
    }

    public KeystoreProperties(String keystorePath, String keystorePass, String alias) {
        this.keystorePath = keystorePath;
        this.keystorePass = keystorePass;
        this.alias = alias;
    }

    public String getKeystorePath() {
        return keystorePath;
    }

    public void setKeystorePath(String keystorePath) {
        this.keystorePath = keystorePath;
    }

    public String getKeystorePass() {
        return keystorePass;
    }

    public void setKeystorePass(String keystorePass) {
        this.keystorePass = keystorePass;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

}
