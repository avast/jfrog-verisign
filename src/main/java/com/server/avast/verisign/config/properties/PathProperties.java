package com.server.avast.verisign.config.properties;

import java.util.Collections;
import java.util.List;

/**
 * @author Vitasek L.
 */
public class PathProperties {
    private boolean caseSensitive = true;
    private boolean expandVirtualReposToLocal = true;
    private List<String> ignorePath = Collections.emptyList();
    private List<String> enabledPath = Collections.emptyList();

    public boolean isCaseSensitive() {
        return caseSensitive;
    }

    public void setCaseSensitive(boolean caseSensitive) {
        this.caseSensitive = caseSensitive;
    }

    public List<String> getIgnorePath() {
        return ignorePath;
    }

    public void setIgnorePath(List<String> ignorePath) {
        this.ignorePath = ignorePath;
    }

    public List<String> getEnabledPath() {
        return enabledPath;
    }

    public void setEnabledPath(List<String> enabledPath) {
        this.enabledPath = enabledPath;
    }

    public boolean isExpandVirtualReposToLocal() {
        return expandVirtualReposToLocal;
    }

    public void setExpandVirtualReposToLocal(boolean expandVirtualReposToLocal) {
        this.expandVirtualReposToLocal = expandVirtualReposToLocal;
    }
}
