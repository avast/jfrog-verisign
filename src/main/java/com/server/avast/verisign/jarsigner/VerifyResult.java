package com.server.avast.verisign.jarsigner;

import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;

/**
 * @author Vitasek L.
 */
public class VerifyResult {
    private List<String> errors = new ArrayList<>();
    private List<String> warnings = new ArrayList<>();
    private List<String> info = new ArrayList<>();

    public VerifyResult() {
    }

    public List<String> getErrors() {
        return errors;
    }

    public void setErrors(List<String> errors) {
        this.errors = errors;
    }

    public List<String> getWarnings() {
        return warnings;
    }

    public void setWarnings(List<String> warnings) {
        this.warnings = warnings;
    }

    public List<String> getInfo() {
        return info;
    }

    public void setInfo(List<String> info) {
        this.info = info;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", VerifyResult.class.getSimpleName() + "[", "]")
                .add("errors=" + errors)
                .add("warnings=" + warnings)
                .add("info=" + info)
                .toString();
    }

    public String joinErrors() {
        return String.join("\n", errors) + "\n" + String.join("\n", warnings);
    }

    public boolean hasAnyErrorsOrWarnings() {
        return !getErrors().isEmpty() || !getWarnings().isEmpty();
    }

}
