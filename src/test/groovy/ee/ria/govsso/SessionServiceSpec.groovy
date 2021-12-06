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

    @Unroll
    @Feature("LOGIN_INIT_ENDPOINT")
    @Feature("LOGIN_INIT_GET_LOGIN")
    def "Incorrect login challenge: #reason"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, paramKey, paramValue)

        Response initLoginResponse = Requests.getRequestWithParams(flow, flow.sessionService.fullInitUrl, paramsMap, Collections.emptyMap())

        assertEquals(statusCode, initLoginResponse.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals(error, initLoginResponse.jsonPath().getString("error"), "Correct error is returned")
        assertTrue(initLoginResponse.jsonPath().getString("message").startsWith(message), "Correct message is returned")

        where:
        reason               | paramKey          | paramValue | statusCode | error                    | message
        "Empty value"        | "login_challenge" | ""         | 400        | "Bad Request"            | "authInit.loginChallenge: only characters and numbers allowed"
        "Illegal characters" | "login_challenge" | "123_!?#"  | 400        | "Bad Request"            | "authInit.loginChallenge: only characters and numbers allowed"
        "Missing parameter"  | ""                | ""         | 400        | "Bad Request"            | "Required request parameter 'login_challenge' for method parameter type String is not present"
        "Incorrect parameter"| "login_"          | "a"*32     | 400        | "Bad Request"            | "Required request parameter 'login_challenge' for method parameter type String is not present"
        "Not matching value" | "login_challenge" | "a"*32     | 500        | "Internal Server Error"  | "404 Not Found from GET"
        "Over maxLength"     | "login_challenge" | "a"*33     | 500        | "Internal Server Error"  | "404 Not Found from GET"
        "Under minLength"    | "login_challenge" | "a"*31     | 500        | "Internal Server Error"  | "404 Not Found from GET"
    }

    @Feature("LOGIN_TARACALLBACK_ENDPOINT")
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

    @Feature("LOGIN_TARACALLBACK_ENDPOINT")
    def "Correct redirect URL with incorrect state parameter is returned from TARA"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)
        Response authenticationFinishedResponse = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "state", "incorrect_state")
        Utils.setParameter(paramsMap, "code", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse,"code"))

        Response sessionServiceResponse = Requests.getRequestWithParams(flow, flow.sessionService.fullTaraCallbackUrl, paramsMap, Collections.emptyMap())

        assertEquals(500, sessionServiceResponse.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals("Invalid TARA callback state", sessionServiceResponse.getBody().jsonPath().get("message"), "Correct error message is returned")
    }

    @Feature("LOGIN_TARACALLBACK_ENDPOINT")
    def "Correct redirect URL with incorrect code parameter is returned from TARA"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)
        Response authenticationFinishedResponse = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "code", "incorrect_code")
        Utils.setParameter(paramsMap, "state", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse,"state"))

        Response sessionServiceResponse = Requests.getRequestWithParams(flow, flow.sessionService.fullTaraCallbackUrl, paramsMap, Collections.emptyMap())

        String errorMessage = "ErrorCode:invalid_grant, Error description:The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client., Status Code:400"

        assertEquals(500, sessionServiceResponse.getStatusCode())
        assertEquals(errorMessage, sessionServiceResponse.getBody().jsonPath().get("message"), "Correct error message is returned")
    }

    @Unroll
    @Feature("LOGIN_TARACALLBACK_ENDPOINT")
    def "Correct redirect URL with incorrect SESSION cookie is returned from TARA: #reason"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)
        Response authenticationFinishedResponse = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)

        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookieMap, cookieKey, cookieValue)

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "state", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse,"state"))
        Utils.setParameter(paramsMap, "code", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse,"code"))

        Response sessionServiceResponse = Requests.getRequestWithCookiesAndParams(flow, flow.sessionService.fullTaraCallbackUrl, cookieMap, paramsMap, Collections.emptyMap())

        assertEquals(statusCode, sessionServiceResponse.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals(error, sessionServiceResponse.jsonPath().getString("error"), "Correct error is returned")
        assertEquals(message, sessionServiceResponse.jsonPath().getString("message"), "Correct message is returned")

        where:
        reason               | cookieKey | cookieValue | statusCode | error                    | message
        "Empty value"        | "SESSION" | ""          | 500        | "Internal Server Error"  | "Missing session attribute 'sso.session' of type SsoSession"
        "Illegal characters" | "SESSION" | "123_!?#"   | 500        | "Internal Server Error"  | "Missing session attribute 'sso.session' of type SsoSession"
        "Not matching value" | "SESSION" | "a"*48      | 500        | "Internal Server Error"  | "Missing session attribute 'sso.session' of type SsoSession"
        "Over maxLength"     | "SESSION" | "a"*49      | 500        | "Internal Server Error"  | "Missing session attribute 'sso.session' of type SsoSession"
        "Under minLength"    | "SESSION" | "a"*47      | 500        | "Internal Server Error"  | "Missing session attribute 'sso.session' of type SsoSession"
    }

    @Unroll
    @Feature("CONSENT_INIT_ENDPOINT")
    def "Incorrect consent challenge: #reason"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, paramKey, paramValue)

        Response consentResponse = Requests.getRequestWithParams(flow, flow.sessionService.fullConsentUrl, paramsMap, Collections.emptyMap())

        assertEquals(statusCode, consentResponse.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals(error, consentResponse.jsonPath().getString("error"), "Correct error is returned")
        assertTrue(consentResponse.jsonPath().getString("message").startsWith(message), "Correct message is returned")

        where:
        reason               | paramKey            | paramValue | statusCode | error                    | message
        "Empty value"        | "consent_challenge" | ""         | 400        | "Bad Request"            | "authConsent.consentChallenge: only characters and numbers allowed"
        "Illegal characters" | "consent_challenge" | "123_!?#"  | 400        | "Bad Request"            | "authConsent.consentChallenge: only characters and numbers allowed"
        "Missing parameter"  | ""                  | ""         | 400        | "Bad Request"            | "Required request parameter 'consent_challenge' for method parameter type String is not present"
        "Incorrect parameter"| "consent_"          | "a"*32     | 400        | "Bad Request"            | "Required request parameter 'consent_challenge' for method parameter type String is not present"
        "Not matching value" | "consent_challenge" | "a"*32     | 500        | "Internal Server Error"  | "404 Not Found from PUT"
        "Over maxLength"     | "consent_challenge" | "a"*33     | 500        | "Internal Server Error"  | "404 Not Found from PUT"
        "Under minLength"    | "consent_challenge" | "a"*31     | 500        | "Internal Server Error"  | "404 Not Found from PUT"
    }
}
