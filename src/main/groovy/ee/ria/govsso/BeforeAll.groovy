package ee.ria.govsso

import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.RestAssured
import io.restassured.filter.log.RequestLoggingFilter
import io.restassured.filter.log.ResponseLoggingFilter

import java.nio.file.Paths

class BeforeAll {
    Properties props = new Properties()

    BeforeAll() {
        URL envFile = this.getClass().getResource('/.env')
        Properties envProperties = new Properties()
        if (envFile) { // Read base test properties from the location specified in .env file
            envFile.withInputStream {
                envProperties.load(it)
            }
            Paths.get(envProperties.getProperty("configuration_base_path"), envProperties.getProperty("configuration_path"), "application.properties").withInputStream {
                props.load(it)
            }
        } else { // Read base test properties from classpath
            this.getClass().getResource('/application.properties').withInputStream {
                props.load(it)
                props.put("env.local", true)
            }
        }

        // Rest Assured settings
        // Log all requests and responses locally and in allure report
        RestAssured.filters(new AllureRestAssured(), new RequestLoggingFilter(), new ResponseLoggingFilter())
        // Relax validation
        RestAssured.useRelaxedHTTPSValidation()
    }
}
