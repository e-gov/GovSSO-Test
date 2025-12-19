package ee.ria.govsso

import ee.ria.govsso.model.Actuator
import ee.ria.govsso.util.ServiceUrls
import io.qameta.allure.Feature
import io.restassured.response.Response
import org.apache.http.HttpStatus
import spock.lang.Issue

import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.is

class MonitoringSpec extends GovSsoSpecification {

    @Feature("HEALTH_MONITORING_ENDPOINT")
    @Feature("HEALTH_MONITORING_ENDPOINT_DEPENDENCIES")
    @Feature("HEALTH_MONITORING_STATUS")
    def "Verify #service Prometheus response"() {
        when:
        Response response = switch (service) {
            case SsoOidcService -> Steps.getActuatorEndpoint(service.fullNodeUrlPrometheus, Actuator.PROMETHEUS_OIDCSERVICE)
            default -> Steps.getPrometheus(service.fullNodeUrl)
        }

        then:
        response.then()
                .contentType("text/plain")
                .body(containsString("process_start_time_seconds"))

        where:
        service << [ServiceUrls.SSO_INPROXY_SERVICE, ServiceUrls.SSO_ADMIN_SERVICE, ServiceUrls.SSO_OIDC_SERVICE]
    }

    @Feature("HEALTH_MONITORING_ENDPOINT")
    @Feature("HEALTH_MONITORING_ENDPOINT_DEPENDENCIES")
    @Feature("HEALTH_MONITORING_STATUS")
    def "Verify #service actuator #endpoint dependent service '#component' status"() {
        expect:
        Steps.getActuatorEndpoint(service.fullNodeUrl, endpoint).then()
                .contentType("application/vnd.spring-boot.actuator")
                .body("components.${component}.status", equalTo("UP"))

        where:
        service                         | endpoint           | component
        ServiceUrls.SSO_SESSION_SERVICE | Actuator.HEALTH    | "hydra"
        ServiceUrls.SSO_SESSION_SERVICE | Actuator.HEALTH    | "tara"
        ServiceUrls.SSO_SESSION_SERVICE | Actuator.READINESS | "hydra"
        ServiceUrls.SSO_SESSION_SERVICE | Actuator.READINESS | "tara"

        ServiceUrls.SSO_INPROXY_SERVICE | Actuator.HEALTH    | "admin"

        ServiceUrls.SSO_ADMIN_SERVICE   | Actuator.HEALTH    | "db"
        ServiceUrls.SSO_ADMIN_SERVICE   | Actuator.HEALTH    | "ldap"
        ServiceUrls.SSO_ADMIN_SERVICE   | Actuator.HEALTH    | "mail"
        ServiceUrls.SSO_ADMIN_SERVICE   | Actuator.READINESS | "db"
        ServiceUrls.SSO_ADMIN_SERVICE   | Actuator.READINESS | "ldap"
    }

    @Feature("HEALTH_MONITORING_ENDPOINT")
    @Feature("HEALTH_MONITORING_ENDPOINT_DEPENDENCIES")
    @Feature("HEALTH_MONITORING_STATUS")
    def "Verify #service actuator #endpoint status"() {
        given:
        def contentType = service instanceof SsoOidcService ? "application/json; charset=utf-8" : "application/vnd.spring-boot.actuator"
        def status = service instanceof SsoOidcService ? "ok" : "UP"

        expect:
        Steps.getActuatorEndpoint(service.fullNodeUrl, endpoint).then()
                .contentType(contentType)
                .body("status", is(status))

        where:
        service                         | endpoint
        ServiceUrls.SSO_SESSION_SERVICE | Actuator.HEALTH
        ServiceUrls.SSO_SESSION_SERVICE | Actuator.READINESS
        ServiceUrls.SSO_SESSION_SERVICE | Actuator.LIVENESS

        ServiceUrls.SSO_INPROXY_SERVICE | Actuator.HEALTH
        ServiceUrls.SSO_INPROXY_SERVICE | Actuator.READINESS
        ServiceUrls.SSO_INPROXY_SERVICE | Actuator.LIVENESS

        ServiceUrls.SSO_ADMIN_SERVICE   | Actuator.HEALTH
        ServiceUrls.SSO_ADMIN_SERVICE   | Actuator.READINESS
        ServiceUrls.SSO_ADMIN_SERVICE   | Actuator.LIVENESS

        ServiceUrls.SSO_OIDC_SERVICE    | Actuator.READINESS_OIDCSERVICE
        ServiceUrls.SSO_OIDC_SERVICE    | Actuator.LIVENESS_OIDCSERVICE
    }

    @Issue("Not able to check OIDC service error 'path'='/notfound'")
    @Feature("HEALTH_MONITORING_ENDPOINT")
    def "#service actuator #endpoint cannot be accessed through proxy"() {
        expect:
        switch (service) {
            case SsoOidcService -> Steps.tryGetActuatorEndpoint(service.fullBaseUrl, endpoint).then()
                    .statusCode(HttpStatus.SC_NOT_FOUND)
//                    .body("path", is("/notfound"))
// Why does not OIDC response 'path' have "/notfound" value like for actuator endpoints?
            default -> Steps.tryGetActuatorEndpoint(service.fullBaseUrl, endpoint).then()
                    .statusCode(HttpStatus.SC_NOT_FOUND)
                    .body("path", is("/notfound"))
        }

        where:
        service                         | endpoint
        ServiceUrls.SSO_SESSION_SERVICE | Actuator.HEALTH
        ServiceUrls.SSO_SESSION_SERVICE | Actuator.READINESS
        ServiceUrls.SSO_SESSION_SERVICE | Actuator.LIVENESS

        ServiceUrls.SSO_OIDC_SERVICE    | Actuator.READINESS_OIDCSERVICE
        ServiceUrls.SSO_OIDC_SERVICE    | Actuator.LIVENESS_OIDCSERVICE
        ServiceUrls.SSO_OIDC_SERVICE    | Actuator.PROMETHEUS_OIDCSERVICE
    }
}
