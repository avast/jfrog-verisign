# jfrog-verisign

- JFrog plugin to verify deploying artifacts signatures. It supports both JAR and RPM (PGP) verification. 

## Project info
- **Project maintainer:** Ladislav Vitásek ([vitasek@avast.com](mailto:vitasek/@/avast.com))
- **Requirements:**
    * Gradle 6.6+
    * JDK 11
    * JFrog 7+

It was tested with JFrog API version `artifactory-api:7.12.5`.  

## Content
[//]: https://imthenachoman.github.io/nGitHubTOC
[//]: https://ecotrust-canada.github.io/markdown-toc/

- [General information](#general-information)
- [Usage](#usage)
    - [Build](#build)
    - [Deploy & Configuration](#deploy--configuration)
- [Verisign.yaml file](#verisignyaml-file)
- [API calls](#api-calls)
   - [Configuration file reload](#configuration-file-reload)
   - [Get current configuration](#get-current-configuration) 

## General information
Plugin is used to verify deploying artifacts signature. If it fails, it returns HTTP status error with a detail message. 
It validates (if enabled) JAR like files (JAR, AAR) and RPM files.
The verification can be applied (via configuration file) only for specific repository paths. 

See more details about [JAR signing](https://docs.oracle.com/javase/tutorial/deployment/jar/signing.html) and [how to sign RPMs with GPG](https://access.redhat.com/articles/3359321).

## How it works

### JAR Verification
For JAR verification the plugin uses (to be more effective) modified JarSigner source code (launching a new JVM process is slow).
Signature is valid if JAR is signed, and it's verified by key stored in PKCS12 keystore. The key is identified by alias.
Make sure the keystore file is accessible for JFrog user (put it into eg. user home).
Unsigned JAR is denied, and it's considered as an error.  

### RPM Verification
RPM utility does verification for RPM files (`rpm -Kv` command). It has to be available on the target OS system.  
The verification is run under JFrog `system` user. 

Unsigned RPM is denied, and it's considered as an error.

## Usage

### Build
Use Gradle command (Windows) 
```bash
   gradlew.bat build
```
or (Linux/Mac)
```bash
   ./gradlew build
```


### Deploy & Configuration
For the steps 1-3 you can use `./gradlew deploy` task, which makes these steps 1-3 for you. Make sure you set correct `artifactoryPath` property in [`gradle.properties`](gradle.properties) file first.

1. Copy `jfrog-verisign.jar` (located in `/build/libs`) into JFrog's `var/etc/artifactory/plugins/lib` directory
2. Copy `verisign.groovy` (located in `/src/main/groovy`) into JFrog's `var/etc/artifactory/plugins`  directory
3. Copy `verisign.yaml` (located in `/etc/verisign.yaml`) into JFrog's `var/etc/artifactory/plugins`  directory
4. Define keystore file (for the JAR verification) and public PGP keys (for RPM verification, eg. use command `sudo rpm --import re.rpm.gpg.public`) on the JFrog's machines
   Make sure the keystore file is accessible for JFrog system user (put it into its eg. user home).
5. Update `verisign.yaml` according to your needs
6. Update `logback.xml` configuration (located at JFrog's `/var/etc/artifactory/logback.xml`) with custom log levels
   ```xml
    <logger name="verisign">
        <level value="debug"/>
    </logger>

    <logger name="com.server.avast.verisign" level="debug">
    </logger>
   ```
7. Restart JFrog


## Verisign.yaml file
See this [example plugin configuration](/etc/verisign.yaml) file.  
It's recommended to link your [`verisign.yaml`](/etc/verisign.yaml) file with this [schema](/etc/verisign-schema.json), it can help you to fix typos and to give you more hints (via ctrl/cmd+space).
See this [tutorial](https://www.jetbrains.com/help/idea/2021.1/json.html?utm_source=product&utm_medium=link&utm_campaign=IU&utm_content=2021.1#ws_json_schema_add_custom).
You can refresh this configuration file using [API call](#configuration-file-reload).

## API Calls
### Configuration file reload
To force **reload** verisign.yaml you can simply call this `curl` command
```
curl -X GET -v -u admin:password "http://localhost:8082/artifactory/api/plugins/execute/refreshVerisignConfig"
```
### Get current configuration
To **get current ignore/enabled repo paths** from verisign.yaml as JSON call:
```
curl -X GET -v -u admin:password "http://localhost:8082/artifactory/api/plugins/execute/verisignConfig"
```

> ⚠ Note: The used user for connection should be an `admin` or the user should be part of the `verisign` group (must exist/be created in JFrog). These pre-defined settings can be changed in the `verisign.groovy` file. 

