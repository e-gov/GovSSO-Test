package ee.ria.govsso

import io.restassured.RestAssured
import io.restassured.filter.log.RequestLoggingFilter
import io.restassured.filter.log.ResponseLoggingFilter
import org.opensaml.core.config.InitializationService
import spock.lang.Shared
import spock.lang.Specification

import java.nio.file.Paths

class GovSsoSpecification extends Specification {
    @Shared
    Properties props = new Properties()
    static String REJECT_ERROR_CODE = "user_cancel"
    static String IDP_USERNAME = "xavi"
    static String IDP_PASSWORD = "creus"
    static String EIDASLOA = "E"

    def setupSpec() {
        InitializationService.initialize()

        URL envFile = this.getClass().getResource('/.env')
        Properties envProperties = new Properties()
        if (envFile) {
            envFile.withInputStream {
                envProperties.load(it)
            }
            Paths.get(envProperties.getProperty("configuration_base_path"), envProperties.getProperty("configuration_path"), "application.properties").withInputStream {
                props.load(it)
            }

            //Log all requests and responses for debugging
            if (envProperties."log_all" && envProperties."log_all" != "false") {
                RestAssured.filters(new RequestLoggingFilter(), new ResponseLoggingFilter())
            }
        } else {
            this.getClass().getResource('/application.properties').withInputStream {
                props.load(it)
            }
        }
    }
}