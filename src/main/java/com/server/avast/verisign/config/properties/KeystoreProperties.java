package com.server.avast.verisign.config.properties;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Collections;
import java.util.List;

/**
 * @author Vitasek L.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class KeystoreProperties {
    private String path;
    private String password = "";
    private List<String> aliases = Collections.emptyList();

    public KeystoreProperties() {
    }

    public KeystoreProperties(String path, String password, List<String> aliases) {
        this.path = path;
        this.password = password;
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

    public List<String> getAliases() {
        return aliases;
    }

    public void setAliases(List<String> aliases) {
        this.aliases = aliases;
    }
}
