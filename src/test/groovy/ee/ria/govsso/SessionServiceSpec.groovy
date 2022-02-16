package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.allOf
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.hasKey
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
    def "Authentication request with valid acr_values parameter: #acrValue:"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        def value = paramsMap.put("acr_values", acrValue)
        Response initOIDCServiceSession = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response response = Steps.followRedirect(flow, initOIDCServiceSession)

        assertEquals(302, response.statusCode(), "Correct HTTP status code is returned")

        where:
        acrValue     | _
        "high"       | _
        "substantial"| _
        "low"        | _
    }

    @Feature("LOGIN_INIT_ENDPOINT")
    def "Authentication request with invalid acr_values parameter"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        def value = paramsMap.put("acr_values", "invalid")
        Response initOIDCServiceSession = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response response = Steps.followRedirect(flow, initOIDCServiceSession)

        assertEquals(400, response.jsonPath().get("status"), "Correct HTTP status code is returned")
        assertEquals("USER_INPUT", response.jsonPath().get("error"), "Correct error is returned")
        assertEquals("Ebakorrektne päring.", response.jsonPath().get("message"), "Correct message is returned")
    }

    @Unroll
    @Feature("LOGIN_INIT_ENDPOINT")
    def "Incorrect login challenge: #reason"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, paramKey, paramValue)

        Response initLoginResponse = Requests.getRequestWithParams(flow, flow.sessionService.fullInitUrl, paramsMap, Collections.emptyMap())

        assertEquals(400, initLoginResponse.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals("USER_INPUT", initLoginResponse.jsonPath().getString("error"), "Correct error is returned")
        assertEquals("Ebakorrektne päring.", initLoginResponse.jsonPath().getString("message"), "Correct message is returned")

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

    @Feature("SECURE_COOKIE_HANDLING")
    @Feature("LOGIN_INIT_ENDPOINT")
    def "Verify session cookie attributes"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response loginInitResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)

        assertThat("Correct cookie attributes", loginInitResponse.getDetailedCookie("__Host-GOVSSO").toString(), allOf(containsString("Path=/"), containsString("HttpOnly"), containsString("Secure"), containsString("Max-Age=3600"), containsString("SameSite=Lax")))
        assertThat("Correct cookie attributes", loginInitResponse.getDetailedCookie("__Host-XSRF-TOKEN").toString(), allOf(containsString("Path=/"), containsString("HttpOnly"), containsString("Secure"), containsString("Max-Age=3600")))
    }

    @Feature("LOGIN_INIT_ENDPOINT")
    def "Verify __Host-GOVSSO JWT cookie elements"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response loginInitResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)

        SignedJWT signedJWT = SignedJWT.parse(loginInitResponse.getCookie("__Host-GOVSSO"))

        assertThat("Cookie contains nonce", signedJWT.getJWTClaimsSet().getClaims(), hasKey("tara_nonce"))
        assertThat("Cookie contains state", signedJWT.getJWTClaimsSet().getClaims(), hasKey("tara_state"))
        assertThat("Cookie contains login challenge", signedJWT.getJWTClaimsSet().getClaims(), hasKey("login_challenge"))
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

        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookieMap, "__Host-GOVSSO", sessionServiceRedirectToTaraResponse.getCookie("__Host-GOVSSO"))
        Utils.setParameter(cookieMap, "__Host-XSRF-TOKEN", sessionServiceRedirectToTaraResponse.getCookie("__Host-XSRF-TOKEN"))

        Response sessionServiceResponse = Requests.getRequestWithCookiesAndParams(flow, flow.sessionService.fullTaraCallbackUrl, cookieMap, paramsMap, Collections.emptyMap())

        assertEquals(400, sessionServiceResponse.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals("USER_INPUT", sessionServiceResponse.getBody().jsonPath().get("error"), "Correct error message is returned")
        assertEquals("Ebakorrektne päring.", sessionServiceResponse.getBody().jsonPath().get("message"), "Correct error message is returned")
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

        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookieMap, "__Host-GOVSSO", sessionServiceRedirectToTaraResponse.getCookie("__Host-GOVSSO"))

        Response sessionServiceResponse = Requests.getRequestWithCookiesAndParams(flow, flow.sessionService.fullTaraCallbackUrl, cookieMap, paramsMap, Collections.emptyMap())

        assertEquals(400, sessionServiceResponse.getStatusCode())
        assertEquals("USER_INPUT", sessionServiceResponse.getBody().jsonPath().get("error"), "Correct error message is returned")
        assertEquals("Ebakorrektne päring.", sessionServiceResponse.getBody().jsonPath().get("message"), "Correct error message is returned")
    }

    @Feature("LOGIN_TARACALLBACK_ENDPOINT")
    def "Taracallback request with missing __Host-GOVSSO cookie"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)
        Response authenticationFinishedResponse = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "code", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "code"))
        Utils.setParameter(paramsMap, "state", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "state"))

        Response sessionServiceResponse = Requests.getRequestWithParams(flow, flow.sessionService.fullTaraCallbackUrl, paramsMap, Collections.emptyMap())

        assertEquals(400, sessionServiceResponse.getStatusCode())
        assertEquals("USER_COOKIE_MISSING", sessionServiceResponse.getBody().jsonPath().get("error"), "Correct error message is returned")
        assertEquals("Küpsis on puudu või kehtivuse kaotanud", sessionServiceResponse.getBody().jsonPath().get("message"), "Correct error message is returned")
    }

    @Unroll
    @Feature("LOGIN_TARACALLBACK_ENDPOINT")
    def "Taracallback request with incorrect __Host-GOVSSO cookie"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)
        Response authenticationFinishedResponse = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)

        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookieMap, "__Host-GOVSSO", "incorrect")

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "state", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "state"))
        Utils.setParameter(paramsMap, "code", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "code"))

        Response sessionServiceResponse = Requests.getRequestWithCookiesAndParams(flow, flow.sessionService.fullTaraCallbackUrl, cookieMap, paramsMap, Collections.emptyMap())

        assertEquals(400, sessionServiceResponse.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals("USER_INPUT", sessionServiceResponse.jsonPath().get("error"), "Correct error is returned")
        assertEquals("Ebakorrektne päring.", sessionServiceResponse.jsonPath().get("message"), "Correct message is returned")
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
        "Empty value"         | "consent_challenge" | ""         | 400    | "USER_INPUT"        | "Ebakorrektne päring."
        "Illegal characters"  | "consent_challenge" | "123_!?#"  | 400    | "USER_INPUT"        | "Ebakorrektne päring."
        "Missing parameter"   | ""                  | ""         | 400    | "USER_INPUT"        | "Ebakorrektne päring."
        "Incorrect parameter" | "consent_"          | "a" * 32   | 400    | "USER_INPUT"        | "Ebakorrektne päring."
        "Not matching value"  | "consent_challenge" | "a" * 32   | 400    | "USER_INPUT"        | "Ebakorrektne päring."
        "Over maxLength"      | "consent_challenge" | "a" * 33   | 400    | "USER_INPUT"        | "Ebakorrektne päring."
        "Under minLength"     | "consent_challenge" | "a" * 31   | 400    | "USER_INPUT"        | "Ebakorrektne päring."
    }

    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Continue session request without existing session"() {
        expect:
        Response oidcAuthenticate = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Response initLogin = Steps.followRedirect(flow, oidcAuthenticate)
        Utils.setParameter(flow.sessionService.cookies, "__Host-GOVSSO", initLogin.getCookie("__Host-GOVSSO"))
        Response continueSession = Requests.postRequestWithCookies(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies)

        assertEquals(403, continueSession.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals("USER_INPUT", continueSession.jsonPath().getString("error"), "Correct error is returned")
        assertEquals("Ebakorrektne päring.", continueSession.jsonPath().getString("message"), "Correct message is returned")
    }

    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Continue session request without __Host-GOVSSO cookie"() {
        expect:
        Response oidcAuthenticate = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcAuthenticate)
        Response continueSession = Requests.postRequestWithCookies(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies)

        assertEquals(403, continueSession.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals("USER_INPUT", continueSession.jsonPath().getString("error"), "Correct error is returned")
        assertEquals("Ebakorrektne päring.", continueSession.jsonPath().getString("message"), "Correct message is returned")

    }

    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Continue session with invalid __Host-GOVSSO cookie"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)

        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcServiceInitResponse)

        Utils.setParameter(flow.sessionService.cookies, "__Host-GOVSSO", "a"*48)
        Response continueWithExistingSession = Requests.postRequestWithCookies(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies)

        assertEquals(403, continueWithExistingSession.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals("USER_INPUT", continueWithExistingSession.jsonPath().getString("error"), "Correct error is returned")
        assertEquals("Ebakorrektne päring.", continueWithExistingSession.jsonPath().getString("message"), "Correct message is returned")
    }

    @Feature("LOGIN_REAUTHENTICATE_ENDPOINT")
    def "Reauthenticate with invalid __Host-GOVSSO cookie"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)

        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcServiceInitResponse)

        Utils.setParameter(flow.sessionService.cookies, "__Host-GOVSSO", "a"*48)
        Response reauthenticateWithExistingSession = Requests.postRequestWithCookies(flow, flow.sessionService.fullReauthenticateUrl, flow.sessionService.cookies)

        assertEquals(403, reauthenticateWithExistingSession.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals("USER_INPUT", reauthenticateWithExistingSession.jsonPath().getString("error"), "Correct error is returned")
        assertEquals("Ebakorrektne päring.", reauthenticateWithExistingSession.jsonPath().getString("message"), "Correct message is returned")
    }

    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Continue session with invalid __Host-XSRF-TOKEN cookie"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)

        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Response initLogin = Steps.followRedirect(flow, oidcServiceInitResponse)

        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))

        Utils.setParameter(flow.sessionService.cookies, "__Host-GOVSSO", initLogin.getCookie("__Host-GOVSSO"))
        Utils.setParameter(flow.sessionService.cookies, "__Host-XSRF-TOKEN", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        Response continueWithExistingSession = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies, formParamsMap)

        assertEquals(403, continueWithExistingSession.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals("USER_INPUT", continueWithExistingSession.jsonPath().getString("error"), "Correct error is returned")
        assertEquals("Ebakorrektne päring.", continueWithExistingSession.jsonPath().getString("message"), "Correct message is returned")
    }

    @Feature("LOGIN_REAUTHENTICATE_ENDPOINT")
    def "Reauthenticate with invalid __Host-XSRF-TOKEN cookie"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)

        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Response initLogin = Steps.followRedirect(flow, oidcServiceInitResponse)

        Utils.setParameter(flow.sessionService.cookies, "__Host-GOVSSO", initLogin.getCookie("__Host-GOVSSO"))
        Utils.setParameter(flow.sessionService.cookies, "__Host-XSRF-TOKEN", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        Response reauthenticateWithExistingSession = Requests.postRequestWithCookies(flow, flow.sessionService.fullReauthenticateUrl, flow.sessionService.cookies)

        assertEquals(403, reauthenticateWithExistingSession.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals("USER_INPUT", reauthenticateWithExistingSession.jsonPath().getString("error"), "Correct error is returned")
        assertEquals("Ebakorrektne päring.", reauthenticateWithExistingSession.jsonPath().getString("message"), "Correct message is returned")
    }

    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Continue session without existing session"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Steps.followRedirect(flow, oidcServiceInitResponse)
        Response continueSessionResponse = Requests.postRequestWithCookies(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies)

        assertEquals(403, continueSessionResponse.jsonPath().get("status"), "Correct HTTP status code is returned")
        assertEquals("USER_INPUT", continueSessionResponse.jsonPath().getString("error"), "Correct error is returned")
        assertEquals("Ebakorrektne päring.", continueSessionResponse.jsonPath().getString("message"), "Correct message is returned")
    }

    @Feature("LOGIN_REAUTHENTICATE_ENDPOINT")
    def "Reauthenticate without existing session"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Steps.followRedirect(flow, oidcServiceInitResponse)
        Response reauthenticateResponse = Requests.postRequestWithCookies(flow, flow.sessionService.fullReauthenticateUrl, flow.sessionService.cookies)

        assertEquals(403, reauthenticateResponse.jsonPath().get("status"), "Correct HTTP status code is returned")
        assertEquals("USER_INPUT", reauthenticateResponse.jsonPath().getString("error"), "Correct error is returned")
        assertEquals("Ebakorrektne päring.", reauthenticateResponse.jsonPath().getString("message"), "Correct message is returned")
    }

    @Feature("LOGIN_INIT_ENDPOINT")
    @Feature("AUTHENTICATION")
    def "Create session in client-A with eIDAS substantial acr and initialize authentication sequence in client-B with high acr"() {
        expect:
        Response createSessionWithEidas = Steps.authenticateWithEidasInGovsso(flow, "substantial", "C")
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, createSessionWithEidas.getBody().jsonPath().get("id_token")).getJWTClaimsSet()

        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Response initLogin = Steps.followRedirect(flow, oidcServiceInitResponse)

        assertEquals("substantial", claims.getClaim("acr"), "Correct acr value in token")
        assertEquals(500, initLogin.jsonPath().get("status"), "Correct status code")
        assertEquals("TECHNICAL_GENERAL", initLogin.jsonPath().get("error"), "Correct error code")
        assertEquals("Protsess ebaõnnestus tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti.", initLogin.jsonPath().get("message"), "Correct message")
    }

}