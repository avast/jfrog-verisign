package com.server.avast.verisign.config.properties;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * @author Vitasek L.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class KeystoreProperties {
    private String path;
    private String password = "";
    private String alias;

    public KeystoreProperties() {
    }

    public KeystoreProperties(String path, String password, String alias) {
        this.path = path;
        this.password = password;
        this.alias = alias;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

}
