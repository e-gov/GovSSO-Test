package ee.ria.govsso

import io.qameta.allure.Feature
import io.restassured.response.Response

import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.notNullValue
import static org.hamcrest.Matchers.hasItems

class MonitoringSpec extends GovSsoSpecification {

    Flow flow = new Flow(props)

    @Feature("MONITORING")
    def "Verify health response elements"() {
        expect:
        Response health = Requests.getHealth(flow)
        health.then()
                .statusCode(200)
                .body("status", is("UP"))
                .body("components.hydra.status", is("UP"))
                .body("components.tara.status", is("UP"))
                .body("components.ping.status.", is("UP"))
                .body("components.livenessState.status.", is("UP"))
                .body("components.readinessState.status.", is("UP"))
                .body("components.truststore.status.", is("UP"))
                .body("components.truststore.components.Hydra.status.", is("UP"))
                .body("components.truststore.components.Hydra.details.certificates.state[0]", is("ACTIVE"))
                .body("components.truststore.components.Hydra.details.certificates.state[1]", is("ACTIVE"))
                .body("components.truststore.components.TARA.status.", is("UP"))
                .body("components.truststore.components.TARA.details.certificates.state[0]", is("ACTIVE"))
                .body("components.truststore.components.TARA.details.certificates.state[1]", is("ACTIVE"))
                .body("groups", hasItems("readiness", "liveness"))
    }

    @Feature("MONITORING")
    def "Verify readiness response elements"() {
        expect:
        Response readiness = Requests.getReadiness(flow)
        readiness.then()
                .statusCode(200)
                .body("status", is("UP"))
                .body("components.hydra.status", is("UP"))
                .body("components.tara.status", is("UP"))
                .body("components.readinessState.status.", is("UP"))
                .body("components.truststore.status.", is("UP"))
                .body("components.truststore.components.Hydra.status.", is("UP"))
                .body("components.truststore.components.Hydra.details.certificates.state[0]", is("ACTIVE"))
                .body("components.truststore.components.Hydra.details.certificates.state[1]", is("ACTIVE"))
                .body("components.truststore.components.TARA.status.", is("UP"))
                .body("components.truststore.components.TARA.details.certificates.state[0]", is("ACTIVE"))
                .body("components.truststore.components.TARA.details.certificates.state[1]", is("ACTIVE"))

    }

    @Feature("MONITORING")
    def "Verify liveness response elements"() {
        expect:
        Response health = Requests.getLiveness(flow)
        health.then()
                .statusCode(200)
                .body("status", is("UP"))
    }

    @Feature("MONITORING")
    def "Verify info response elements"() {
        expect:
        Response info = Requests.getInfo(flow)
        info.then()
                .statusCode(200)
                .body("git.branch", notNullValue())
                .body("git.commit.id", notNullValue())
                .body("git.commit.time", notNullValue())
                .body("git.build.time", notNullValue())
                .body("git.build.version", notNullValue())
                .body("git.build.number", notNullValue())
                .body("build.artifact", is("govsso-session"))
                .body("build.name", is("GovSSO Session Service"))
                .body("build.time", notNullValue())
                .body("build.version", notNullValue())
                .body("build.group", is("ee.ria.govsso"))
                .body("startTime", notNullValue())
                .body("currentTime", notNullValue())
    }
}
