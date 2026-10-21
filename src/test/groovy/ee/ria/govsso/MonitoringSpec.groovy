package ee.ria.govsso

import ee.ria.govsso.model.Actuator
import io.qameta.allure.Feature
import io.restassured.response.Response
import org.apache.http.HttpStatus
import spock.lang.Requires
import spock.lang.Tag

import java.time.Duration
import java.time.Instant

import static ee.ria.govsso.util.ServiceUrls.*
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

@Tag("monitoring")
class MonitoringSpec extends GovSsoSpecification {

    @Feature("MONITORING")
    def "#service actuator #endpoint status is UP"(BaseService service, Actuator endpoint) {
        when:
        Response response = Steps.getActuatorEndpoint(service.fullNodeUrl, endpoint)

        then:
        assertThat("Correct content type", response.contentType, is("application/vnd.spring-boot.actuator.v3+json"))
        assertThat("Correct status", response.path("status") as String, is("UP"))

        where:
        service            | endpoint
        SESSION_SERVICE    | Actuator.HEALTH
        SESSION_SERVICE    | Actuator.LIVENESS
        SESSION_SERVICE    | Actuator.READINESS
        INPROXY_SERVICE    | Actuator.HEALTH
        INPROXY_SERVICE    | Actuator.LIVENESS
        INPROXY_SERVICE    | Actuator.READINESS
        ADMIN_SERVICE      | Actuator.HEALTH
        ADMIN_SERVICE      | Actuator.LIVENESS
        ADMIN_SERVICE      | Actuator.READINESS
        ENDUSERSELFSERVICE | Actuator.HEALTH
        ENDUSERSELFSERVICE | Actuator.LIVENESS
        ENDUSERSELFSERVICE | Actuator.READINESS
    }

    @Feature("MONITORING")
    def "#service health components are UP"(BaseService service, List<String> components) {
        when:
        Response health = Steps.getActuatorEndpoint(service.fullNodeUrl, Actuator.HEALTH)
        Map<String, Map> actual = health.path("components") as Map

        then:
        assertThat("Correct health components", actual.keySet(), equalTo(components as Set))
        // Session reports Pääsuke as UNKNOWN until the first Pääsuke request.
        (components - ["paasuke"]).each { component ->
            assertThat("Component '${component}' is UP".toString(), actual[component].status as String, is("UP"))
        }

        where:
        service            | components
        SESSION_SERVICE    | ["diskSpace", "hydra", "livenessState", "paasuke", "ping", "readinessState", "tara", "truststore"]
        INPROXY_SERVICE    | ["admin", "certificates", "diskSpace", "livenessState", "ping", "readinessState", "refreshScope"]
        ADMIN_SERVICE      | ["db", "diskSpace", "livenessState", "mail", "ping", "readinessState"]
        ENDUSERSELFSERVICE | ["certificates", "diskSpace", "govssoSession", "ignite", "livenessState", "ping", "readinessState", "tara"]
    }

    @Feature("MONITORING")
    def "#service readiness group contains expected components"(BaseService service, List<String> components) {
        when:
        Response readiness = Steps.getActuatorEndpoint(service.fullNodeUrl, Actuator.READINESS)

        then:
        assertThat("Correct readiness components", (readiness.path("components") as Map).keySet(), equalTo(components as Set))

        where:
        service            | components
        SESSION_SERVICE    | ["hydra", "readinessState", "tara", "truststore"]
        INPROXY_SERVICE    | ["certificates", "diskSpace", "readinessState", "refreshScope"]
        ADMIN_SERVICE      | ["db", "diskSpace", "readinessState"]
        ENDUSERSELFSERVICE | ["certificates", "diskSpace", "govssoSession", "ignite", "readinessState", "tara"]
    }

    @Feature("MONITORING")
    def "#service certificate store '#store' is UP"(BaseService service, String store) {
        when:
        Response health = Steps.getActuatorEndpoint(service.fullNodeUrl, Actuator.HEALTH)

        then:
        assertThat("Correct store status", health.path("components.${store}.status" as String) as String, is("UP"))

        where:
        service            | store
        SESSION_SERVICE    | "truststore.components.TARA"
        SESSION_SERVICE    | "truststore.components.Hydra"
        INPROXY_SERVICE    | "certificates.components.adminTrustStore"
        INPROXY_SERVICE    | "certificates.components.gatewayTrustStore"
        INPROXY_SERVICE    | "certificates.components.serverKeyStore"
        ENDUSERSELFSERVICE | "certificates.components.govssoSessionTrustStore"
        ENDUSERSELFSERVICE | "certificates.components.igniteKeyStore"
        ENDUSERSELFSERVICE | "certificates.components.igniteTrustStore"
        ENDUSERSELFSERVICE | "certificates.components.taraTrustStore"
    }

    @Feature("MONITORING")
    def "#service actuator info contains build and git details"(BaseService service, String artifact, String name, String group) {
        when:
        Response info = Steps.getActuatorEndpoint(service.fullNodeUrl, Actuator.INFO)

        then:
        assertThat("Correct build artifact", info.path("build.artifact") as String, is(artifact))
        assertThat("Correct build name", info.path("build.name") as String, is(name))
        assertThat("Correct build group", info.path("build.group") as String, is(group))
        assertThat("Git commit id is present", info.path("git.commit.id"), notNullValue())

        where:
        service            | artifact                    | name                           | group
        SESSION_SERVICE    | "govsso-session"            | "GovSSO Session Service"       | "ee.ria.govsso"
        INPROXY_SERVICE    | "tara-govsso-inproxy"       | "TARA/GovSSO Incoming Proxy"   | "ee.ria.govsso"
        ADMIN_SERVICE      | "tara-admin-api"            | "tara-admin-api"               | "ee.ria.tara-admin"
        ENDUSERSELFSERVICE | "govsso-enduserselfservice" | "GovSSO End User Self-Service" | "ee.ria.govsso"
    }

    @Feature("MONITORING")
    def "#service actuator info reports start and current time"(BaseService service) {
        when:
        Response info = Steps.getActuatorEndpoint(service.fullNodeUrl, Actuator.INFO)
        Instant startTime = Instant.parse(info.path("startTime") as String)
        Instant currentTime = Instant.parse(info.path("currentTime") as String)

        then:
        assertThat("Start time is not after current time", startTime.isAfter(currentTime), is(false))
        assertThat("Current time matches test clock",
                Duration.between(currentTime, Instant.now()).abs(), lessThanOrEqualTo(Duration.ofMinutes(5)))

        where:
        // Admin has no start and current time info contributor.
        service << [SESSION_SERVICE, INPROXY_SERVICE, ENDUSERSELFSERVICE]
    }

    @Feature("MONITORING")
    def "#service actuator prometheus returns metrics"(BaseService service) {
        when:
        Response response = Steps.getActuatorEndpoint(service.fullNodeUrl, Actuator.PROMETHEUS)

        then:
        assertThat("Correct content type", response.contentType, startsWith("text/plain"))
        assertThat("Contains process metrics", response.body.asString(), containsString("process_start_time_seconds"))

        where:
        // Session and EndUserSelfService have no Prometheus registry.
        service << [INPROXY_SERVICE, ADMIN_SERVICE]
    }

    @Feature("MONITORING")
    @Requires({ isLoadBalancer(data.service as BaseService) })
    def "#service actuator #endpoint is not reachable through service URL"(BaseService service, Actuator endpoint) {
        when:
        Response response = Steps.tryGetActuatorEndpoint(service.fullBaseUrl, endpoint)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(HttpStatus.SC_NOT_FOUND))

        where:
        service            | endpoint
        SESSION_SERVICE    | Actuator.HEALTH
        SESSION_SERVICE    | Actuator.LIVENESS
        SESSION_SERVICE    | Actuator.READINESS
        SESSION_SERVICE    | Actuator.INFO
        SESSION_SERVICE    | Actuator.PROMETHEUS
        INPROXY_SERVICE    | Actuator.HEALTH
        INPROXY_SERVICE    | Actuator.LIVENESS
        INPROXY_SERVICE    | Actuator.READINESS
        INPROXY_SERVICE    | Actuator.INFO
        INPROXY_SERVICE    | Actuator.PROMETHEUS
        ENDUSERSELFSERVICE | Actuator.HEALTH
        ENDUSERSELFSERVICE | Actuator.LIVENESS
        ENDUSERSELFSERVICE | Actuator.READINESS
        ENDUSERSELFSERVICE | Actuator.INFO
        ENDUSERSELFSERVICE | Actuator.PROMETHEUS
    }

    @Feature("MONITORING")
    def "Hydra #port port #endpoint reports ok"(String port, String baseUrl, String endpoint) {
        when:
        Response response = Steps.tryGetMonitoringEndpoint(baseUrl, endpoint)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(HttpStatus.SC_OK))
        assertThat("Correct content type", response.contentType, startsWith("application/json"))
        assertThat("Correct status", response.path("status") as String, is("ok"))

        where:
        port     | baseUrl                       | endpoint
        "admin"  | SSO_OIDC_SERVICE.fullAdminUrl | "/health/alive"
        "admin"  | SSO_OIDC_SERVICE.fullAdminUrl | "/health/ready"
        "public" | SSO_OIDC_SERVICE.fullNodeUrl  | "/health/alive"
        "public" | SSO_OIDC_SERVICE.fullNodeUrl  | "/health/ready"
    }

    @Feature("MONITORING")
    def "Hydra admin port version endpoint returns version"() {
        when:
        Response response = Steps.tryGetMonitoringEndpoint(SSO_OIDC_SERVICE.fullAdminUrl, "/version")

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(HttpStatus.SC_OK))
        assertThat("Correct content type", response.contentType, startsWith("application/json"))
        assertThat("Correct version format", response.path("version") as String, matchesPattern("\\d+\\.\\d+\\.\\d+.*"))
    }

    @Feature("MONITORING")
    def "Hydra admin port prometheus endpoint returns metrics"() {
        when:
        Response response = Steps.tryGetMonitoringEndpoint(SSO_OIDC_SERVICE.fullAdminUrl, "/admin/metrics/prometheus")

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(HttpStatus.SC_OK))
        assertThat("Correct content type", response.contentType, startsWith("text/plain"))
        assertThat("Contains Go runtime metrics", response.body.asString(), containsString("go_info"))
        assertThat("Contains Hydra request metrics", response.body.asString(), containsString('app="hydra"'))
    }

    @Feature("MONITORING")
    def "Hydra #endpoint is not exposed on public port"(String endpoint) {
        when:
        Response response = Steps.tryGetMonitoringEndpoint(SSO_OIDC_SERVICE.fullNodeUrl, endpoint)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(HttpStatus.SC_NOT_FOUND))

        where:
        endpoint << ["/version", "/admin/metrics/prometheus"]
    }

    @Feature("MONITORING")
    def "Hydra #endpoint is not reachable through InProxy"(String endpoint) {
        when:
        Response response = Steps.tryGetMonitoringEndpoint(INPROXY_SERVICE.fullBaseUrl, endpoint)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(HttpStatus.SC_NOT_FOUND))

        where:
        endpoint << ["/health/alive", "/health/ready", "/version", "/admin/metrics/prometheus"]
    }
}
