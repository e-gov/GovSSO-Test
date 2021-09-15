package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll

import static org.hamcrest.Matchers.emptyOrNullString
import static org.hamcrest.Matchers.not
import static org.junit.jupiter.api.Assertions.*
import static org.hamcrest.MatcherAssert.assertThat

class GovSsoDemoTestSpec extends GovSsoSpecification {

    FlowTara flow = new FlowTara(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Unroll
    @Feature("AUTHENTICATION")
    def "authentication with Mobile-ID"() {
        expect:
        //TODO: Start authentication in GOVSSO until redirect to TARA

        //Authenticate in TARA with Mid
        Response authenticationFinishedResponse = Steps.authenticateWithMidInTARA(flow, "60001017716", "69100366")

        //TODO: Follow redirects in GOVSSO and assert
        assertEquals(302, authenticationFinishedResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat("Authorization code should be returned", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "code"), not(emptyOrNullString()))
    }

    @Unroll
    @Feature("AUTHENTICATION")
    def "authenticate with Smart-ID"() {
        expect:
        //TODO: Start authentication in GOVSSO until redirect to TARA

        //Authenticate in TARA with Sid
        Response authenticationFinishedResponse = Steps.authenticateWithSidInTARA(flow, "30303039914")

        //TODO: Follow redirects in GOVSSO and assert
        assertEquals(302, authenticationFinishedResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat("Authorization code should be returned", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "code"), not(emptyOrNullString()))
    }

    @Unroll
    @Feature("AUTHENTICATION")
    def "authenticate with Eidas"() {
        expect:
        //TODO: Start authentication in GOVSSO until redirect to TARA

        //Authenticate in TARA with eIDAS
        Response authenticationFinishedResponse = Steps.authenticateWithEidasInTARA(flow, "CA", IDP_USERNAME, IDP_PASSWORD, EIDASLOA)

        //TODO: Follow redirects in GOVSSO and assert
        assertEquals(302, authenticationFinishedResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat("Authorization code should be returned", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "code"), not(emptyOrNullString()))
    }

    @Unroll
    @Feature("AUTHENTICATION")
    def "authenticate with ID-Card"() {
        expect:
        //TODO: Start authentication in GOVSSO until redirect to TARA

        //Authenticate in TARA with ID-Card
        Response authenticationFinishedResponse = Steps.authenticateWithIdCardInTARA(flow)

        //TODO: Follow redirects in GOVSSO and assert
        assertEquals(302, authenticationFinishedResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat("Authorization code should be returned", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "code"), not(emptyOrNullString()))
    }
}
