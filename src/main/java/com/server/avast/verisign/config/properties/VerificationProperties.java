package com.server.avast.verisign.config.properties;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * @author Vitasek L.
 */
public class VerificationProperties {
    private int errorHttpResponseCode = 400;
    private String additionalErrorMessage;
    private boolean enableJarVerification = true;
    private boolean enableRpmVerification = true;
    private String rpmCommand = "rpm -Kv";
    private List<String> ignorePath = Collections.emptyList();
    private List<String> enabledPath = Collections.emptyList();
    private List<String> verifyJarExtensions = Arrays.asList("jar", "aar");

    public String getAdditionalErrorMessage() {
        return additionalErrorMessage;
    }

    public void setAdditionalErrorMessage(String additionalErrorMessage) {
        this.additionalErrorMessage = additionalErrorMessage;
    }

    public List<String> getIgnorePath() {
        return ignorePath;
    }

    public void setIgnorePath(List<String> ignorePath) {
        this.ignorePath = ignorePath;
    }

    public int getErrorHttpResponseCode() {
        return errorHttpResponseCode;
    }

    public void setErrorHttpResponseCode(int errorHttpResponseCode) {
        this.errorHttpResponseCode = errorHttpResponseCode;
    }

    public List<String> getVerifyJarExtensions() {
        return verifyJarExtensions;
    }

    public void setVerifyJarExtensions(List<String> verifyJarExtensions) {
        this.verifyJarExtensions = verifyJarExtensions;
    }

    public List<String> getEnabledPath() {
        return enabledPath;
    }

    public void setEnabledPath(List<String> enabledPath) {
        this.enabledPath = enabledPath;
    }

    public String getRpmCommand() {
        return rpmCommand;
    }

    public void setRpmCommand(String rpmCommand) {
        this.rpmCommand = rpmCommand;
    }

    public boolean isEnableJarVerification() {
        return enableJarVerification;
    }

    public void setEnableJarVerification(boolean enableJarVerification) {
        this.enableJarVerification = enableJarVerification;
    }

    public boolean isEnableRpmVerification() {
        return enableRpmVerification;
    }

    public void setEnableRpmVerification(boolean enableRpmVerification) {
        this.enableRpmVerification = enableRpmVerification;
    }
}
