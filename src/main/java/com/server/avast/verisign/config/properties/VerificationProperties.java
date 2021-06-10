package com.server.avast.verisign.config.properties;

/**
 * @author Vitasek L.
 */
public class VerificationProperties {
    private int errorHttpResponseCode = 400;
    private String additionalErrorMessage;
    private boolean nonBlockingMode = false;
    private VerifyJarProperties jar = new VerifyJarProperties();
    private VerifyRpmProperties rpm = new VerifyRpmProperties();
    private PathProperties paths = new PathProperties();

    public String getAdditionalErrorMessage() {
        return additionalErrorMessage;
    }

    public void setAdditionalErrorMessage(String additionalErrorMessage) {
        this.additionalErrorMessage = additionalErrorMessage;
    }

    public int getErrorHttpResponseCode() {
        return errorHttpResponseCode;
    }

    public void setErrorHttpResponseCode(int errorHttpResponseCode) {
        this.errorHttpResponseCode = errorHttpResponseCode;
    }


    public VerifyJarProperties getJar() {
        return jar;
    }

    public void setJar(VerifyJarProperties jar) {
        this.jar = jar;
    }

    public VerifyRpmProperties getRpm() {
        return rpm;
    }

    public void setRpm(VerifyRpmProperties rpm) {
        this.rpm = rpm;
    }

    public PathProperties getPaths() {
        return paths;
    }

    public void setPaths(PathProperties paths) {
        this.paths = paths;
    }

    public boolean isNonBlockingMode() {
        return nonBlockingMode;
    }

    public void setNonBlockingMode(boolean nonBlockingMode) {
        this.nonBlockingMode = nonBlockingMode;
    }
}
