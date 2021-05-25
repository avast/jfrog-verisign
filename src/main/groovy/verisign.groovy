import com.fasterxml.jackson.databind.ObjectMapper
import com.server.avast.verisign.config.Config
import com.server.avast.verisign.service.VerificationService
import groovy.transform.Field
import org.artifactory.fs.ItemInfo

@Field final String PROPERTIES_FILE_PATH = "plugins/verisign.yaml"
@Field final Config config = new Config(new File(ctx.getArtifactoryHome().getEtcDir(), PROPERTIES_FILE_PATH))
@Field VerificationService verificationSupport = new VerificationService(config, repositories, ctx)

executions {
    refreshVerisignConfig(version: '1.0', httpMethod: 'GET', users:["admin"],  groups:["verisign"]) { params ->
        log.info("Verisign - Reloading config from path ${PROPERTIES_FILE_PATH}")
        try {
            config.reload()
            message = """{result: "DONE"}"""
            status = 200
        } catch (Exception e) {
            log.error("Failed to reload Verisign plugin config from path ${PROPERTIES_FILE_PATH}", e)
            final Map<String, Object> map = new HashMap<>()
            map.put("result", "FAILED")
            map.put("errorMessage", e.getMessage())
            message = new ObjectMapper().writeValueAsString(map)
            status = 500
        }
    }

    verisignConfig(version: '1.0', httpMethod: 'GET', users:["admin"],  groups:["verisign"]) {  params ->
        final Map<String, Object> map = new HashMap<>()

        def verification = config.getProperties().getVerification()
        map.put("enabledPath", verification.getEnabledPath())
        map.put("ignorePath", verification.getIgnorePath())
        message = new ObjectMapper().writeValueAsString(map)
        status = 200
    }
}

storage {
    afterCreate { ItemInfo item ->
        if (!item.isFolder()) {
            asSystem {
                verificationSupport.verify(item)
            }
        }
    }
}

