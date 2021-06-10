package com.server.avast.verisign.config.properties;

import java.util.Collections;
import java.util.List;

/**
 * @author Vitasek L.
 */
public class VerifyRpmProperties {
    private String rpmCommand = "rpm -Kv";
    private boolean enabled = true;
    private List<String> pgpKeyIds = Collections.emptyList();

    public String getRpmCommand() {
        return rpmCommand;
    }

    public void setRpmCommand(String rpmCommand) {
        this.rpmCommand = rpmCommand;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public List<String> getPgpKeyIds() {
        return pgpKeyIds;
    }

    public void setPgpKeyIds(List<String> pgpKeyIds) {
        this.pgpKeyIds = pgpKeyIds;
    }
}
