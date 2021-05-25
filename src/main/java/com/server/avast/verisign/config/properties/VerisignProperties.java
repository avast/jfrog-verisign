package com.server.avast.verisign.config.properties;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * @author Vitasek L.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class VerisignProperties {
    private VerificationProperties verification;

    public VerificationProperties getVerification() {
        return verification;
    }

    public void setVerification(VerificationProperties verification) {
        this.verification = verification;
    }
}
