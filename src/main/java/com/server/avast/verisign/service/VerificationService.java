package com.server.avast.verisign.service;

import com.server.avast.verisign.config.Config;
import com.server.avast.verisign.config.properties.KeystoreProperties;
import com.server.avast.verisign.config.properties.VerificationProperties;
import com.server.avast.verisign.jarsigner.VerifyResult;
import com.server.avast.verisign.utils.JarSignerUtils;
import com.server.avast.verisign.utils.RpmVerifier;
import org.artifactory.api.context.ArtifactoryContext;
import org.artifactory.exception.CancelException;
import org.artifactory.fs.ItemInfo;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.AntPathMatcher;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

/**
 * @author Vitasek L.
 */
public class VerificationService {
    private static final Logger logger = LoggerFactory.getLogger(VerificationService.class);
    private final Config config;
    private final Repositories repositories;
    private final File dataDir;
    private final AntPathMatcher antPathMatcher;
    private final RpmVerifier rpmVerifier;

    public VerificationService(Config config, Repositories repositories, ArtifactoryContext artifactoryContext) {
        this.config = config;
        this.repositories = repositories;
        dataDir = artifactoryContext.getArtifactoryHome().getDataDir();
        antPathMatcher = new AntPathMatcher("/");
        antPathMatcher.setCachePatterns(true);
        rpmVerifier = new RpmVerifier(config);
    }

    public void verify(ItemInfo itemInfo) {
        final RepoPath repoPath = itemInfo.getRepoPath();
        if (itemInfo.isFolder() || !repoPath.isFile()) {
            return;
        }

        final String path = repoPath.toPath();
        logger.debug("Verify file path: {}", path);

        final VerificationProperties verification = config.getProperties().getVerification();
        final boolean enabledPath = verification.getEnabledPath().isEmpty() ||
                verification.getEnabledPath().stream().anyMatch(pattern -> antPathMatcher.match(pattern, path));

        final Optional<String> ignoredByPrefix = verification.getIgnorePath().stream().
                filter(ignorePath -> antPathMatcher.match(ignorePath, path)).findAny();
        if (ignoredByPrefix.isPresent()) {
            logger.debug("Verification ignored by Ant path for {} with pattern {}", repoPath.toPath(), ignoredByPrefix.get());
            return;
        }

        if (enabledPath) {
            if (verification.isEnableJarVerification()) {
                final boolean hasJarSupportedExtension = verification.getVerifyJarExtensions().stream().
                        anyMatch(extension -> path.endsWith("." + extension));
                if (hasJarSupportedExtension) {
                    verifyJar(repoPath, path);
                }
            } else {
                if (verification.isEnableRpmVerification()) {
                    if (path.endsWith(".rpm")) {
                        verifyRpm(repoPath, path);
                    }
                } else {
                    logger.debug("Rpm verification is disabled");
                }
            }
        }
    }

    private void verifyRpm(RepoPath repoPath, String path) {
        try {
            final File file = getPhysicalPath(repoPath);
            final VerifyResult result = file.exists() ?
                    rpmVerifier.verify(file) :
                    rpmVerifier.verify(repositories.getContent(repoPath));

            if (result.hasAnyErrorsOrWarnings()) {
                final VerificationProperties verification = config.getProperties().getVerification();
                final String additionalMessage = Optional.ofNullable(verification.getAdditionalErrorMessage()).
                        map(item -> "\n" + item).orElse("");
                throw new CancelException("Failed to verify RPM artifact: " + path +
                        " . Error(s): " + result.joinErrors() + additionalMessage,
                        verification.getErrorHttpResponseCode());
            }
        } catch (IOException e) {
            logger.error("Failed to verify RPM file {}", path, e);
            throw new CancelException("Failed to verify " + path + " " + e.getMessage(), 503);
        }
    }

    private void verifyJar(RepoPath repoPath, String path) {
        logger.info("Going to verify JAR repopath {}", path);

        try {
            final KeystoreProperties keystore = config.getProperties().getKeystore();
            final File file = getPhysicalPath(repoPath);
            final VerifyResult result = file.exists() ?
                    JarSignerUtils.verify(file, keystore) :
                    JarSignerUtils.verify(repositories.getContent(repoPath), keystore);

            if (result.hasAnyErrorsOrWarnings()) {
                final VerificationProperties verification = config.getProperties().getVerification();
                final String additionalMessage = Optional.ofNullable(verification.getAdditionalErrorMessage()).
                        map(item -> "\n" + item).orElse("");
                throw new CancelException("Failed to verify JAR artifact: " + path +
                        " . Error(s): " + result.joinErrors() + additionalMessage,
                        verification.getErrorHttpResponseCode());
            }
        } catch (IOException e) {
            logger.error("Failed to verify JAR file {}", path, e);
            throw new CancelException("Failed to verify " + path + " " + e.getMessage(), 503);
        }
    }

    @NotNull
    private File getPhysicalPath(RepoPath repoPath) {
        final String sha1 = repositories.getFileInfo(repoPath).getChecksumsInfo().getSha1();
        final String shaPrefix = sha1.substring(0, 2);
        final Path physicicalPath = Paths.get(dataDir.getAbsolutePath(), "filestore", shaPrefix, sha1);

        return physicicalPath.toFile();
    }
}
