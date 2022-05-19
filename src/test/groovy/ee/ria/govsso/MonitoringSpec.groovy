package ee.ria.govsso

import io.qameta.allure.Feature
import io.restassured.response.Response
import org.hamcrest.Matchers

import static org.junit.jupiter.api.Assertions.*

class MonitoringSpec extends GovSsoSpecification {

    Flow flow = new Flow(props)

    @Feature("")
    def "Verify health response elements"() {
        expect:
        Response health = Requests.getHealth(flow)
        health.then()
                .body("status", Matchers.is("UP"))
                .body("components.hydra.status", Matchers.is("UP"))
                .body("components.ping.status.", Matchers.is("UP"))
                .body("components.livenessState.status.", Matchers.is("UP"))
                .body("components.readinessState.status.", Matchers.is("UP"))
                .body("groups", Matchers.hasItems("readiness", "liveness"))

        assertEquals(200, health.statusCode(), "Correct health HTTP status code is returned")
    }

    @Feature("")
    def "Verify readiness response elements"() {
        expect:
        Response readiness = Requests.getReadiness(flow)
        readiness.then()
                .body("status", Matchers.oneOf("UP", "DOWN"))

        assertEquals(200, readiness.statusCode(), "Correct health HTTP status code is returned")
    }

    @Feature("")
    def "Verify info response elements"() {
        expect:
        Response info = Requests.getInfo(flow)
        info.then()
                .body("git.branch", Matchers.notNullValue())
                .body("git.commit.id", Matchers.notNullValue())
                .body("git.commit.time", Matchers.notNullValue())
                .body("build.artifact", Matchers.is("govsso-session"))
                .body("build.name", Matchers.is("GOVSSO Session Service"))
                .body("build.time", Matchers.notNullValue())
                .body("build.version", Matchers.notNullValue())
                .body("build.group", Matchers.is("ee.ria.govsso"))
    }
}