package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.junit.jupiter.api.Assertions.assertEquals
import static org.junit.jupiter.api.Assertions.assertTrue

class SessionServiceSpec extends GovSsoSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Feature("SESSION_SERVICE")
    def "Correct request with query parameters from session service to TARA"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)

        assertEquals(302, sessionServiceRedirectToTaraResponse.getStatusCode(), "Correct HTTP status code is returned")
        assertTrue(sessionServiceRedirectToTaraResponse.getHeader("location").contains("scope"), "Query parameters contain scope")
        assertTrue(sessionServiceRedirectToTaraResponse.getHeader("location").contains("response_type"), "Query parameters contain response_type")
        assertTrue(sessionServiceRedirectToTaraResponse.getHeader("location").contains("redirect_uri"), "Query parameters contain redirect_uri")
        assertTrue(sessionServiceRedirectToTaraResponse.getHeader("location").contains("state"), "Query parameters contain state")
        assertTrue(sessionServiceRedirectToTaraResponse.getHeader("location").contains("nonce"), "Query parameters contain nonce")
        assertTrue(sessionServiceRedirectToTaraResponse.getHeader("location").contains("client_id"), "Query parameters contain client_id")
    }
    @Feature("SESSION_SERVICE")
    def "Correct request with query parameters from TARA is returned to session service"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)
        Response authenticationFinishedResponse = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)

        assertEquals(302, authenticationFinishedResponse.getStatusCode(), "Correct HTTP status code is returned")
        assertTrue(authenticationFinishedResponse.getHeader("location").startsWith(flow.sessionService.getFullTaraCallbackUrl()), "Correct URL is returned")
        assertTrue(authenticationFinishedResponse.getHeader("location").contains("code"), "Query parameters contain code")
        assertTrue(authenticationFinishedResponse.getHeader("location").contains("scope"), "Query parameters contain scope")
        assertTrue(authenticationFinishedResponse.getHeader("location").contains("state"), "Query parameters contain state")
        assertEquals(Utils.getParamValueFromResponseHeader(sessionServiceRedirectToTaraResponse, "state"), Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "state"), "Query contains correct state parameter value")
    }

    @Feature("SESSION_SERVICE")
    def "Correct redirect URL with incorrect state parameter is returned from TARA"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)
        Response authenticationFinishedResponse = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "state", "incorrect_state")
        Utils.setParameter(paramsMap, "code", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse,"code"))
        Utils.setParameter(paramsMap, "scope", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "scope"))

        Response sessionServiceResponse = Requests.getRequestWithParams(flow, flow.sessionService.fullTaraCallbackUrl, paramsMap, Collections.emptyMap())

        assertEquals(500, sessionServiceResponse.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals("Invalid TARA callback state", sessionServiceResponse.getBody().jsonPath().get("message"), "Correct error message is returned")
    }

    @Feature("SESSION_SERVICE")
    def "Correct redirect URL with incorrect code parameter is returned from TARA"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)
        Response authenticationFinishedResponse = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "code", "incorrect_code")
        Utils.setParameter(paramsMap, "state", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse,"state"))
        Utils.setParameter(paramsMap, "scope", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "scope"))

        Response sessionServiceResponse = Requests.getRequestWithParams(flow, flow.sessionService.fullTaraCallbackUrl, paramsMap, Collections.emptyMap())

        String errorMessage = "ErrorCode:invalid_grant, Error description:The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client., Status Code:400"

        assertEquals(500, sessionServiceResponse.getStatusCode())
        assertEquals(errorMessage, sessionServiceResponse.getBody().jsonPath().get("message"), "Correct error message is returned")
    }

    @Feature("SESSION_SERVICE")
    def "Correct redirect URL with incorrect SESSION cookie is returned from TARA"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)
        Response authenticationFinishedResponse = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)

        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookieMap,"SESSION", "incorrect_session_cookie")

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "state", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse,"state"))
        Utils.setParameter(paramsMap, "code", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse,"code"))
        Utils.setParameter(paramsMap, "scope", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "scope"))

        Response sessionServiceResponse = Requests.getRequestWithCookiesAndParams(flow, flow.sessionService.fullTaraCallbackUrl, cookieMap, paramsMap, Collections.emptyMap())

        assertEquals(500, sessionServiceResponse.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals("Missing session attribute 'sso.session' of type SsoSession", sessionServiceResponse.getBody().jsonPath().get("message"), "Correct error message is returned")
    }

}
