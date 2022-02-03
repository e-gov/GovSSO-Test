package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll

import static org.junit.jupiter.api.Assertions.assertEquals
import static org.junit.jupiter.api.Assertions.assertTrue

class SessionServiceSpec extends GovSsoSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Feature("LOGIN_INIT_REDIRECT_TO_TARA")
    def "Correct request with query parameters from session service to TARA"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)

        assertEquals(302, sessionServiceRedirectToTaraResponse.getStatusCode(), "Correct HTTP status code is returned")
        assertTrue(sessionServiceRedirectToTaraResponse.getHeader("location").contains("scope"), "Query parameters contain scope")
        assertTrue(sessionServiceRedirectToTaraResponse.getHeader("location").contains("response_type"), "Query parameters contain response_type")
        assertTrue(sessionServiceRedirectToTaraResponse.getHeader("location").contains("redirect_uri"), "Query parameters contain redirect_uri")
        assertTrue(sessionServiceRedirectToTaraResponse.getHeader("location").contains("state"), "Query parameters contain state")
        assertTrue(sessionServiceRedirectToTaraResponse.getHeader("location").contains("nonce"), "Query parameters contain nonce")
        assertTrue(sessionServiceRedirectToTaraResponse.getHeader("location").contains("client_id"), "Query parameters contain client_id")
    }

    @Unroll
    @Feature("LOGIN_INIT_ENDPOINT")
    @Feature("LOGIN_INIT_GET_LOGIN")
    def "Incorrect login challenge: #reason"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, paramKey, paramValue)

        Response initLoginResponse = Requests.getRequestWithParams(flow, flow.sessionService.fullInitUrl, paramsMap, Collections.emptyMap())

        assertEquals(400, initLoginResponse.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals("USER_INPUT", initLoginResponse.jsonPath().getString("error"), "Correct error is returned")
        assertEquals("Invalid request.", initLoginResponse.jsonPath().getString("message"), "Correct message is returned")

        where:
        reason                | paramKey          | paramValue
        "Empty value"         | "login_challenge" | ""
        "Illegal characters"  | "login_challenge" | "123_!?#"
        "Missing parameter"   | ""                | ""
        "Incorrect parameter" | "login_"          | "a" * 32
        "Not matching value"  | "login_challenge" | "a" * 32
        "Over maxLength"      | "login_challenge" | "a" * 33
        "Under minLength"     | "login_challenge" | "a" * 31
    }

    @Feature("LOGIN_TARACALLBACK_ENDPOINT")
    def "Correct request with query parameters from TARA is returned to session service"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)
        Response authenticationFinishedResponse = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)

        assertEquals(302, authenticationFinishedResponse.getStatusCode(), "Correct HTTP status code is returned")
        assertTrue(authenticationFinishedResponse.getHeader("location").startsWith(flow.sessionService.getFullTaraCallbackUrl()), "Correct URL is returned")
        assertTrue(authenticationFinishedResponse.getHeader("location").contains("code"), "Query parameters contain code")
        assertTrue(authenticationFinishedResponse.getHeader("location").contains("scope"), "Query parameters contain scope")
        assertTrue(authenticationFinishedResponse.getHeader("location").contains("state"), "Query parameters contain state")
        assertEquals(Utils.getParamValueFromResponseHeader(sessionServiceRedirectToTaraResponse, "state"), Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "state"), "Query contains correct state parameter value")
    }

    @Feature("LOGIN_TARACALLBACK_ENDPOINT")
    def "Correct redirect URL with incorrect state parameter is returned from TARA"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)
        Response authenticationFinishedResponse = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "state", "")
        Utils.setParameter(paramsMap, "code", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "code"))

        Response sessionServiceResponse = Requests.getRequestWithParams(flow, flow.sessionService.fullTaraCallbackUrl, paramsMap, Collections.emptyMap())

        assertEquals(400, sessionServiceResponse.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals("USER_INPUT", sessionServiceResponse.getBody().jsonPath().get("error"), "Correct error message is returned")
        assertEquals("Invalid request.", sessionServiceResponse.getBody().jsonPath().get("message"), "Correct error message is returned")
    }

    @Feature("LOGIN_TARACALLBACK_ENDPOINT")
    def "Correct redirect URL with incorrect code parameter is returned from TARA"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)
        Response authenticationFinishedResponse = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "code", "")
        Utils.setParameter(paramsMap, "state", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "state"))

        Response sessionServiceResponse = Requests.getRequestWithParams(flow, flow.sessionService.fullTaraCallbackUrl, paramsMap, Collections.emptyMap())

        assertEquals(400, sessionServiceResponse.getStatusCode())
        assertEquals("USER_INPUT", sessionServiceResponse.getBody().jsonPath().get("error"), "Correct error message is returned")
        assertEquals("Invalid request.", sessionServiceResponse.getBody().jsonPath().get("message"), "Correct error message is returned")
    }

    @Unroll
    @Feature("LOGIN_TARACALLBACK_ENDPOINT")
    def "Correct redirect URL with incorrect SESSION cookie is returned from TARA: #reason"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)
        Response authenticationFinishedResponse = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)

        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookieMap, cookieKey, cookieValue)

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "state", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "state"))
        Utils.setParameter(paramsMap, "code", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "code"))

        Response sessionServiceResponse = Requests.getRequestWithCookiesAndParams(flow, flow.sessionService.fullTaraCallbackUrl, cookieMap, paramsMap, Collections.emptyMap())

        assertEquals(500, sessionServiceResponse.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals("TECHNICAL_GENERAL", sessionServiceResponse.jsonPath().getString("error"), "Correct error is returned")
        assertEquals("An unexpected error occurred. Please try again later.", sessionServiceResponse.jsonPath().getString("message"), "Correct message is returned")

        where:
        reason               | cookieKey | cookieValue
        "Empty value"        | "SESSION" | ""
        "Illegal characters" | "SESSION" | "123_!?#"
        "Not matching value" | "SESSION" | "a" * 48
        "Over maxLength"     | "SESSION" | "a" * 49
        "Under minLength"    | "SESSION" | "a" * 47
    }

    @Unroll
    @Feature("CONSENT_INIT_ENDPOINT")
    def "Incorrect consent challenge: #reason"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, paramKey, paramValue)

        Response consentResponse = Requests.getRequestWithParams(flow, flow.sessionService.fullConsentUrl, paramsMap, Collections.emptyMap())

        assertEquals(status, consentResponse.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals(error, consentResponse.jsonPath().getString("error"), "Correct error is returned")
        assertEquals(errorMessage, consentResponse.jsonPath().getString("message"), "Correct message is returned")

        where:
        reason                | paramKey            | paramValue | status | error               | errorMessage
        "Empty value"         | "consent_challenge" | ""         | 400    | "USER_INPUT"        | "Invalid request."
        "Illegal characters"  | "consent_challenge" | "123_!?#"  | 400    | "USER_INPUT"        | "Invalid request."
        "Missing parameter"   | ""                  | ""         | 400    | "USER_INPUT"        | "Invalid request."
        "Incorrect parameter" | "consent_"          | "a" * 32   | 400    | "USER_INPUT"        | "Invalid request."
        "Not matching value"  | "consent_challenge" | "a" * 32   | 400    | "USER_INPUT"        | "Invalid request."
        "Over maxLength"      | "consent_challenge" | "a" * 33   | 400    | "USER_INPUT"        | "Invalid request."
        "Under minLength"     | "consent_challenge" | "a" * 31   | 400    | "USER_INPUT"        | "Invalid request."
    }

    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Continue session request without existing session"() {
        expect:
        Response oidcAuthenticate = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcAuthenticate)
        Response continueSession = Requests.postRequestWithCookies(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies)

        assertEquals(400, continueSession.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals("USER_INPUT", continueSession.jsonPath().getString("error"), "Correct error is returned")
        assertEquals("Invalid request.", continueSession.jsonPath().getString("message"), "Correct message is returned")
    }

    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Continue session with invalid session cookie"() {
        expect:
        Steps.authenticateWithMidInGovsso(flow)

        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcServiceInitResponse)

        Utils.setParameter(flow.sessionService.cookies, "SESSION", "a"*48)
        Response continueWithExistingSession = Requests.postRequestWithCookies(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies)

        assertEquals(500, continueWithExistingSession.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals("TECHNICAL_GENERAL", continueWithExistingSession.jsonPath().getString("error"), "Correct error is returned")
        assertEquals("An unexpected error occurred. Please try again later.", continueWithExistingSession.jsonPath().getString("message"), "Correct message is returned")
    }

    @Feature("LOGIN_REAUTHENTICATE_ENDPOINT")
    def "Reauthenticate with invalid session cookie"() {
        expect:
        Steps.authenticateWithMidInGovsso(flow)

        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcServiceInitResponse)

        Utils.setParameter(flow.sessionService.cookies, "SESSION", "a"*48)
        Response reauthenticateWithExistingSession = Requests.postRequestWithCookies(flow, flow.sessionService.fullReauthenticateUrl, flow.sessionService.cookies)

        assertEquals(500, reauthenticateWithExistingSession.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals("TECHNICAL_GENERAL", reauthenticateWithExistingSession.jsonPath().getString("error"), "Correct error is returned")
        assertEquals("An unexpected error occurred. Please try again later.", reauthenticateWithExistingSession.jsonPath().getString("message"), "Correct message is returned")
    }

    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Continue session without existing session"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Steps.followRedirect(flow, oidcServiceInitResponse)
        Response continueSessionResponse = Requests.postRequestWithCookies(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies)

        assertEquals(400, continueSessionResponse.jsonPath().get("status"), "Correct HTTP status code is returned")
        assertEquals("USER_INPUT", continueSessionResponse.jsonPath().getString("error"), "Correct error is returned")
        assertEquals("Invalid request.", continueSessionResponse.jsonPath().getString("message"), "Correct message is returned")
    }

    @Feature("LOGIN_REAUTHENTICATE_ENDPOINT")
    def "Reauthenticate without existing session"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Steps.followRedirect(flow, oidcServiceInitResponse)
        Response reauthenticateResponse = Requests.postRequestWithCookies(flow, flow.sessionService.fullReauthenticateUrl, flow.sessionService.cookies)

        assertEquals(400, reauthenticateResponse.jsonPath().get("status"), "Correct HTTP status code is returned")
        assertEquals("USER_INPUT", reauthenticateResponse.jsonPath().getString("error"), "Correct error is returned")
        assertEquals("Invalid request.", reauthenticateResponse.jsonPath().getString("message"), "Correct message is returned")
    }
}