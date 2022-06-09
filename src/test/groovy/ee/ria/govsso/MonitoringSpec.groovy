package ee.ria.govsso

import io.qameta.allure.Feature
import io.restassured.response.Response
import org.hamcrest.Matchers

class MonitoringSpec extends GovSsoSpecification {

    Flow flow = new Flow(props)

    @Feature("MONITORING")
    def "Verify health response elements"() {
        expect:
        Response health = Requests.getHealth(flow)
        health.then()
                .statusCode(200)
                .body("status", Matchers.is("UP"))
                .body("components.hydra.status", Matchers.is("UP"))
                .body("components.tara.status", Matchers.is("UP"))
                .body("components.ping.status.", Matchers.is("UP"))
                .body("components.livenessState.status.", Matchers.is("UP"))
                .body("components.readinessState.status.", Matchers.is("UP"))
                .body("components.truststore.status.", Matchers.is("UP"))
                .body("components.truststore.components.Hydra.status.", Matchers.is("UP"))
                .body("components.truststore.components.Hydra.details.certificates.state[0]", Matchers.is("ACTIVE"))
                .body("components.truststore.components.Hydra.details.certificates.state[1]", Matchers.is("ACTIVE"))
                .body("components.truststore.components.TARA.status.", Matchers.is("UP"))
                .body("components.truststore.components.TARA.details.certificates.state[0]", Matchers.is("ACTIVE"))
                .body("components.truststore.components.TARA.details.certificates.state[1]", Matchers.is("ACTIVE"))
                .body("groups", Matchers.hasItems("readiness", "liveness"))
    }

    @Feature("MONITORING")
    def "Verify readiness response elements"() {
        expect:
        Response readiness = Requests.getReadiness(flow)
        readiness.then()
                .statusCode(200)
                .body("status", Matchers.is("UP"))
                .body("components.hydra.status", Matchers.is("UP"))
                .body("components.tara.status", Matchers.is("UP"))
                .body("components.readinessState.status.", Matchers.is("UP"))
                .body("components.truststore.status.", Matchers.is("UP"))
                .body("components.truststore.components.Hydra.status.", Matchers.is("UP"))
                .body("components.truststore.components.Hydra.details.certificates.state[0]", Matchers.is("ACTIVE"))
                .body("components.truststore.components.Hydra.details.certificates.state[1]", Matchers.is("ACTIVE"))
                .body("components.truststore.components.TARA.status.", Matchers.is("UP"))
                .body("components.truststore.components.TARA.details.certificates.state[0]", Matchers.is("ACTIVE"))
                .body("components.truststore.components.TARA.details.certificates.state[1]", Matchers.is("ACTIVE"))

    }

    @Feature("MONITORING")
    def "Verify liveness response elements"() {
        expect:
        Response health = Requests.getLiveness(flow)
        health.then()
                .statusCode(200)
                .body("status", Matchers.is("UP"))
    }

    @Feature("MONITORING")
    def "Verify info response elements"() {
        expect:
        Response info = Requests.getInfo(flow)
        info.then()
                .statusCode(200)
                .body("git.branch", Matchers.notNullValue())
                .body("git.commit.id", Matchers.notNullValue())
                .body("git.commit.time", Matchers.notNullValue())
                .body("git.build.time", Matchers.notNullValue())
                .body("git.build.version", Matchers.notNullValue())
                .body("git.build.number", Matchers.notNullValue())
                .body("build.artifact", Matchers.is("govsso-session"))
                .body("build.name", Matchers.is("GOVSSO Session Service"))
                .body("build.time", Matchers.notNullValue())
                .body("build.version", Matchers.notNullValue())
                .body("build.group", Matchers.is("ee.ria.govsso"))
                .body("startTime", Matchers.notNullValue())
                .body("currentTime", Matchers.notNullValue())
    }
}