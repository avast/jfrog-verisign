package com.server.avast.verisign.utils;

import com.server.avast.verisign.config.Config;
import com.server.avast.verisign.jarsigner.VerifyResult;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.artifactory.resource.ResourceStreamHandle;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * @author Vitasek L.
 */
public class RpmVerifier {

    private static final Logger logger = LoggerFactory.getLogger(RpmVerifier.class);
    private final Config config;

    public RpmVerifier(Config config) {
        this.config = config;
    }

    public static void main(String[] args) {
        final RpmVerifier rpmVerifier = new RpmVerifier(new Config(new File("etc/verisign.yaml")));
        final VerifyResult verifyResult = rpmVerifier.verify(new File(args[0]));
        System.out.println("verifyResult = " + verifyResult);
    }

    public VerifyResult verifyWithTempFile(ResourceStreamHandle resourceStreamHandle) throws IOException {
        return ResourceHandleUtils.createTempFile(resourceStreamHandle, this::verify);
    }

    public VerifyResult verify(ResourceStreamHandle resourceStreamHandle) throws IOException {
        return ResourceHandleUtils.createTempFile(resourceStreamHandle, file -> {
            try (final InputStream inputStream = resourceStreamHandle.getInputStream()) {
                return verify(inputStream);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public VerifyResult verify(InputStream inputStream) {
        final String[] rpmCommand = getRpmCommand();
        final ProcessBuilder pb = new ProcessBuilder(ArrayUtils.add(rpmCommand, "/dev/stdin"));
        pb.redirectErrorStream(true);
        pb.redirectOutput(ProcessBuilder.Redirect.INHERIT);

        final Process process;
        try {
            process = pb.start();

            try (final OutputStream stdin = process.getOutputStream()) {
                IOUtils.copy(inputStream, stdin);
                stdin.flush();
            }

            return parseRpmProcessOutput(process);
        } catch (IOException | InterruptedException e) {
            logger.error("Failed to run RPM utility to verify RPM", e);
            throw new RuntimeException("Failed to run RPM utility to verify RPM", e);
        }
    }

    public VerifyResult verify(File file) {
        final String[] rpmCommand = getRpmCommand();

        final ProcessBuilder pb = new ProcessBuilder(ArrayUtils.add(rpmCommand, file.getAbsolutePath()));
        pb.redirectErrorStream(true);

        final Process process;
        try {
            process = pb.start();

            return parseRpmProcessOutput(process);

        } catch (IOException | InterruptedException e) {
            logger.error("Failed to run RPM utility to verify RPM", e);
            throw new RuntimeException("Failed to run RPM utility to verify RPM", e);
        }
    }

    private String[] getRpmCommand() {
        return config.getProperties().getVerification().getRpm().getRpmCommand().split(" ");
    }

    @NotNull
    private VerifyResult parseRpmProcessOutput(Process process) throws InterruptedException, IOException {
        if (process.waitFor(20, TimeUnit.SECONDS)) {
            final List<String> response = IOUtils.readLines(process.getInputStream(), StandardCharsets.UTF_8);
            final VerifyResult verifyResult = new VerifyResult();
            if (process.exitValue() != 0) {
                final List<String> errors = verifyResult.getErrors();
                errors.add("RPM signature verification failed");
                errors.addAll(response);
            } else {
                // result code is 0 - ALL OK
                final List<String> pgpKeyIds = config.getProperties().getVerification().getRpm().getPgpKeyIds();
                final boolean isSigned = response.stream().skip(1).filter(line -> {
                    final String lineUpperCase = line.toUpperCase(Locale.ENGLISH);
                    return pgpKeyIds.stream().anyMatch(key -> lineUpperCase.contains(("Signature, key ID " + key + ": OK").toUpperCase(Locale.ENGLISH)));
                }).count() == 2;// header and body
                if (isSigned) {
                    verifyResult.getInfo().addAll(response);
                } else {
                    final List<String> errors = verifyResult.getErrors();
                    errors.add("RPM file is not signed by given keys " + String.join(",", pgpKeyIds));
                    errors.addAll(response);
                }
            }
            return verifyResult;
        } else {
            throw new RuntimeException("Failed to run RPM utility to verify RPM - timeout");
        }
    }

}
