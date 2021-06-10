package com.server.avast.verisign.service;

import com.server.avast.verisign.config.VerisignPropertiesProvider;
import com.server.avast.verisign.config.properties.KeystoreProperties;
import com.server.avast.verisign.config.properties.PathProperties;
import com.server.avast.verisign.config.properties.VerificationProperties;
import com.server.avast.verisign.jarsigner.VerifyResult;
import com.server.avast.verisign.utils.JarSignerUtils;
import com.server.avast.verisign.utils.RpmVerifier;
import org.apache.commons.lang.StringUtils;
import org.artifactory.api.context.ArtifactoryContext;
import org.artifactory.api.repo.RepositoryService;
import org.artifactory.descriptor.repo.LocalRepoDescriptor;
import org.artifactory.descriptor.repo.VirtualRepoDescriptor;
import org.artifactory.exception.CancelException;
import org.artifactory.fs.ItemInfo;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.AntPathMatcher;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * @author Vitasek L.
 */
public class VerificationService {
    private static final Logger logger = LoggerFactory.getLogger(VerificationService.class);
    private final VerisignPropertiesProvider config;
    private final Repositories repositories;
    private final File dataDir;
    private final AntPathMatcher antPathMatcher;
    private final RpmVerifier rpmVerifier;
    private final RepositoryService repositoryService;

    public VerificationService(VerisignPropertiesProvider config, Repositories repositories,
                               ArtifactoryContext artifactoryContext) {
        this.config = config;
        this.repositories = repositories;
        dataDir = artifactoryContext.getArtifactoryHome().getDataDir();
        antPathMatcher = new AntPathMatcher("/");
        antPathMatcher.setCachePatterns(true);
        rpmVerifier = new RpmVerifier(config);
        repositoryService = artifactoryContext.getRepositoryService();
    }

    private static boolean endsWithCaseSensitive(boolean caseSensitive, String path, String endsWith) {
        return caseSensitive ? path.endsWith(endsWith) : StringUtils.endsWithIgnoreCase(path, endsWith);
    }

    public void verify(ItemInfo itemInfo) {
        final RepoPath repoPath = itemInfo.getRepoPath();
        if (itemInfo.isFolder() || !repoPath.isFile()) {
            return;
        }

        verifyPath(repoPath);
    }

    private void verifyPath(RepoPath repoPath) {
        final VerificationProperties verification = config.getProperties().getVerification();
        if (!verification.getJar().isEnabled() && !verification.getRpm().isEnabled()) {
            logger.trace("Verification is disabled");
            return;
        }

        final String path = repoPath.toPath();
        logger.trace("Verify file path: {}", path);

        final PathProperties paths = verification.getPaths();

        antPathMatcher.setCaseSensitive(paths.isCaseSensitive());

        final boolean enabledPath = paths.getEnabledPath().isEmpty() ||
                expandVirtualRepositoriesToLocalIfEnabled(paths.getEnabledPath()).
                        anyMatch(pattern -> antPathMatcher.match(pattern, path));

        if (!enabledPath) {
            logger.trace("Verification is not enabled for this repo path {}", path);
            return;
        }

        final Optional<String> ignoredByPath = expandVirtualRepositoriesToLocalIfEnabled(paths.getIgnorePath()).
                filter(ignorePath -> antPathMatcher.match(ignorePath, path)).findAny();
        if (ignoredByPath.isPresent()) {
            logger.debug("Verification ignored by Ant path for {} with pattern {}", repoPath.toPath(), ignoredByPath.get());
            return;
        }

        if (verification.getJar().isEnabled()) {
            final boolean hasJarSupportedExtension = verification.getJar().getExtensions().stream().
                    anyMatch(extension -> endsWithCaseSensitive(paths.isCaseSensitive(), path, "." + extension));
            if (hasJarSupportedExtension) {
                verifyJar(repoPath, path);
            }
        } else {
            logger.trace("Jar verification is disabled");
        }

        if (verification.getRpm().isEnabled()) {
            if (endsWithCaseSensitive(paths.isCaseSensitive(), path, ".rpm")) {
                verifyRpm(repoPath, path);
            }
        } else {
            logger.trace("Rpm verification is disabled");
        }

    }

    private void verifyRpm(RepoPath repoPath, String path) {
        logger.debug("Going to verify RPM repopath {}", path);
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
            } else {
                logger.debug("RPM artifact with repopath {} is verified succesfuly", path);
            }
        } catch (IOException e) {
            logger.error("Failed to verify RPM file {}", path, e);
            throw new CancelException("Failed to verify " + path + " " + e.getMessage(), e, 503);
        }
    }

    void verifyJar(RepoPath repoPath, String path) {
        logger.debug("Going to verify JAR repopath {}", path);

        try {
            final KeystoreProperties keystore = config.getProperties().getVerification().getJar().getKeystore();
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
            } else {
                logger.debug("JAR artifact with repopath {} is verified succesfuly", path);
            }
        } catch (IOException e) {
            logger.error("Failed to verify JAR file {}", path, e);
            throw new CancelException("Failed to verify " + path + " " + e.getMessage(), e, 503);
        }
    }

    private File getPhysicalPath(RepoPath repoPath) {
        final String sha1 = repositories.getFileInfo(repoPath).getChecksumsInfo().getSha1();
        final String shaPrefix = sha1.substring(0, 2);
        final Path physicicalPath = Paths.get(dataDir.getAbsolutePath(), "filestore", shaPrefix, sha1);

        return physicicalPath.toFile();
    }

    private Stream<String> expandVirtualRepositoriesToLocalIfEnabled(final List<String> antPaths) {
        if (config.getProperties().getVerification().getPaths().isExpandVirtualReposToLocal()) {
            return antPaths.stream().flatMap(antPath -> {
                final String repoKeyPrefix = StringUtils.substringBefore(antPath, "/");
                return getLocalRepositories(repoKeyPrefix).distinct().map(localRepo -> {
                    if (localRepo.equals(repoKeyPrefix)) {
                        return antPath;
                    } else {
                        return StringUtils.replaceOnce(antPath, repoKeyPrefix, localRepo);
                    }
                });
            });
        }
        return antPaths.stream();
    }

    private Stream<String> getLocalRepositories(final String repoKeyPrefix) {
        if (isVirtualRepo(repoKeyPrefix)) {
            final VirtualRepoDescriptor virtualRepoDescriptor = repositoryService.virtualRepoDescriptorByKey(repoKeyPrefix);
            final LocalRepoDescriptor defaultDeploymentRepo = virtualRepoDescriptor.getDefaultDeploymentRepo();
            return Stream.of(defaultDeploymentRepo.getKey());
        } else {
            return Stream.of(repoKeyPrefix);
        }
    }

    private boolean isVirtualRepo(final String repo) {
        if (repo == null) {
            return false;
        }
        return repositoryService.isVirtualRepoExist(repo);
    }
}
