package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.junit.jupiter.api.Assertions.*

class UserInterfaceSpec extends GovSsoSpecification{

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Feature("AUTHENTICATION")
    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Correct buttons and user information in new login sequence"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Response initLoginResponse = Steps.followRedirect(flow, oidcServiceInitResponse)

        String buttonContinueSession = initLoginResponse.body().htmlPath().getString("**.find { button -> button.@formaction == '/login/continuesession'}")
        String buttonReauthenticate = initLoginResponse.body().htmlPath().getString("**.find { button -> button.@formaction == '/login/reauthenticate'}")
        String buttonBackToClient = initLoginResponse.body().htmlPath().getString("**.find { button -> button.@formaction == '/login/reject'}")
        assertEquals("Jätka seanssi", buttonContinueSession, "Continue button exists with correct form action")
        assertEquals("Autendi uuesti", buttonReauthenticate, "Reauthenticate button exists with correct form action")
        assertEquals("Tagasi teenusepakkuja juurde", buttonBackToClient, "Back to service provider link exists with correct form action")
    }

    @Feature("LOGOUT")
    def "Continue session and end session buttons in logout sequence"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)
        Response continueWithExistingSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueWithExistingSession.jsonPath().get("id_token")

        Response initLogoutOidc = Steps.startLogout(flow, idToken, flow.oidcClientB.fullBaseUrl)
        Response initLogoutSession = Steps.followRedirect(flow, initLogoutOidc)

        String buttonEndSession = initLogoutSession.body().htmlPath().getString("**.find { button -> button.@formaction == '/logout/endsession'}")
        String buttonContinueSession = initLogoutSession.body().htmlPath().getString("**.find { button -> button.@formaction == '/logout/continuesession'}")
        assertEquals("Logi kõikidest välja", buttonEndSession, "Reauthenticate button exists with correct form action")
        assertEquals("Jätka seanssi", buttonContinueSession, "Continue button exists with correct form action")
    }
}
