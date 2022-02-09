package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.junit.jupiter.api.Assertions.assertEquals

class UserInterfaceSpec extends GovSsoSpecification{

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Feature("AUTHENTICATION")
    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Continue session and reauthenticate buttons"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Response initLoginResponse = Steps.followRedirect(flow, oidcServiceInitResponse)

        String buttonContinueSession = initLoginResponse.body().htmlPath().getString("**.find { button -> button.@formaction == '/login/continuesession'}")
        String buttonReauthenticate = initLoginResponse.body().htmlPath().getString("**.find { button -> button.@formaction == '/login/reauthenticate'}")
        assertEquals("Continue session", buttonContinueSession, "Continue button exists with correct form action")
        assertEquals("Authenticate again", buttonReauthenticate, "Reauthenticate button exists with correct form action")
    }
}
