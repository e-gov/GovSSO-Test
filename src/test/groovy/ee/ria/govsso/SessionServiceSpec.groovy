package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll

import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.hasKey
import static org.hamcrest.Matchers.allOf
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.MatcherAssert.assertThat

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
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)

        assertThat("Correct HTTP status code", initLogin.statusCode, is(302))
        assertThat("Query parameters contain scope", initLogin.getHeader("location").contains("scope"))
        assertThat("Query parameters contain response_type", initLogin.getHeader("location").contains("response_type"))
        assertThat("Query parameters contain redirect_uri", initLogin.getHeader("location").contains("redirect_uri"))
        assertThat("Query parameters contain state", initLogin.getHeader("location").contains("state"))
        assertThat("Query parameters contain nonce", initLogin.getHeader("location").contains("nonce"))
        assertThat("Query parameters contain client_id", initLogin.getHeader("location").contains("client_id"))
        assertThat("Query parameters contain govsso_login_challenge", initLogin.getHeader("location").contains("govsso_login_challenge"))
        assertThat("Query parameters contain ui_locales", initLogin.getHeader("location").contains("ui_locales"))
        assertThat("Query parameters contain acr_values", initLogin.getHeader("location").contains("acr_values"))
    }

    @Unroll
    @Feature("LOGIN_INIT_ENDPOINT")
    def "Authentication request with valid acr_values parameter: #acrValue:"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap.put("acr_values", acrValue)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.followRedirect(flow, oidcAuth)

        assertThat("Correct HTTP status code", initLogin.statusCode, is(302))

        where:
        acrValue      | _
        "high"        | _
        "substantial" | _
        "low"         | _
    }

    @Feature("LOGIN_INIT_ENDPOINT")
    def "Authentication request with invalid acr_values parameter"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap.put("acr_values", "invalid")
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.followRedirect(flow, oidcAuth)

        assertThat("Correct HTTP status code", initLogin.statusCode, is(400))
        assertThat("Correct error", initLogin.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct error message", initLogin.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Unroll
    @Feature("LOGIN_INIT_ENDPOINT")
    def "Incorrect login challenge: #reason"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, paramKey, paramValue)

        Response initLogin = Requests.getRequestWithParams(flow, flow.sessionService.fullInitUrl, paramsMap)

        assertThat("Correct HTTP status code", initLogin.statusCode, is(400))
        assertThat("Correct error", initLogin.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct error message", initLogin.jsonPath().getString("message"), is("Ebakorrektne päring."))

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
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap << [ui_locales: "et"]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)

        assertThat("Correct cookie attributes", initLogin.getDetailedCookie("__Host-AUTH").toString(), allOf(containsString("Path=/"), containsString("HttpOnly"), containsString("Secure"), containsString("Max-Age=3600"), containsString("SameSite=Lax")))
        assertThat("Correct cookie attributes", initLogin.getDetailedCookie("__Host-XSRF-TOKEN").toString(), allOf(containsString("Path=/"), containsString("HttpOnly"), containsString("Secure"), containsString("Max-Age=3600")))
        assertThat("Correct cookie attributes", initLogin.getDetailedCookie("__Host-LOCALE").toString(), allOf(containsString("Path=/"), containsString("Secure")))
    }

    @Feature("SECURE_COOKIE_HANDLING")
    @Feature("LOGIN_INIT_ENDPOINT")
    def "Verify __Host-AUTH JWT cookie elements"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)

        SignedJWT signedJWT = SignedJWT.parse(initLogin.getCookie("__Host-AUTH"))

        assertThat("Cookie contains nonce", signedJWT.getJWTClaimsSet().claims, hasKey("tara_nonce"))
        assertThat("Cookie contains state", signedJWT.getJWTClaimsSet().claims, hasKey("tara_state"))
        assertThat("Cookie contains login challenge", signedJWT.getJWTClaimsSet().claims, hasKey("login_challenge"))
    }

    @Unroll
    @Feature("LOGIN_INIT_ENDPOINT")
    def "Correct ui_locales passed on to __Host-LOCALE cookie: #uiLocales"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap.put("ui_locales", uiLocales)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)

        assertThat("Correct ui_locale passed to cookie", initLogin.getCookie("__Host-LOCALE"), is(uiLocales))

        where:
        _ | uiLocales
        _ | "et"
        _ | "en"
        _ | "ru"
    }

    @Feature("LOGIN_TARACALLBACK_ENDPOINT")
    def "Correct request with query parameters from TARA is returned to session service"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)

        assertThat("Correct HTTP status code", taraAuthentication.statusCode, is(303))
        assertThat("Correct URL", taraAuthentication.getHeader("location").startsWith(flow.sessionService.getFullTaraCallbackUrl()))
        assertThat("Query parameters contain code", taraAuthentication.getHeader("location").contains("code"))
        assertThat("Query parameters contain scope", taraAuthentication.getHeader("location").contains("scope"))
        assertThat("Query parameters contain state", taraAuthentication.getHeader("location").contains("state"))
        assertThat("Query contains correct state parameter value", Utils.getParamValueFromResponseHeader(initLogin, "state"), is(Utils.getParamValueFromResponseHeader(taraAuthentication, "state")))
    }

    @Feature("LOGIN_TARACALLBACK_ENDPOINT")
    def "Correct redirect URL with incorrect state parameter is returned from TARA"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "state", "")
        Utils.setParameter(paramsMap, "code", Utils.getParamValueFromResponseHeader(taraAuthentication, "code"))

        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookieMap, "__Host-AUTH", initLogin.getCookie("__Host-AUTH"))
        Utils.setParameter(cookieMap, "__Host-XSRF-TOKEN", initLogin.getCookie("__Host-XSRF-TOKEN"))

        Response taracallback = Requests.getRequestWithCookiesAndParams(flow, flow.sessionService.fullTaraCallbackUrl, cookieMap, paramsMap)

        assertThat("Correct HTTP status code", taracallback.statusCode, is(400))
        assertThat("Correct error", taracallback.body.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct error message", taracallback.body.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGIN_TARACALLBACK_ENDPOINT")
    def "Correct redirect URL with incorrect code parameter is returned from TARA"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "code", "")
        Utils.setParameter(paramsMap, "state", Utils.getParamValueFromResponseHeader(taraAuthentication, "state"))

        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookieMap, "__Host-AUTH", initLogin.getCookie("__Host-AUTH"))
        Utils.setParameter(cookieMap, "__Host-XSRF-TOKEN", initLogin.getCookie("__Host-XSRF-TOKEN"))

        Response taracallback = Requests.getRequestWithCookiesAndParams(flow, flow.sessionService.fullTaraCallbackUrl, cookieMap, paramsMap)

        assertThat("Correct HTTP status code", taracallback.statusCode, is(400))
        assertThat("Correct error", taracallback.body.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct error message", taracallback.body.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("SECURE_COOKIE_HANDLING")
    @Feature("LOGIN_TARACALLBACK_ENDPOINT")
    def "Taracallback request with missing __Host-AUTH cookie"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "code", Utils.getParamValueFromResponseHeader(taraAuthentication, "code"))
        Utils.setParameter(paramsMap, "state", Utils.getParamValueFromResponseHeader(taraAuthentication, "state"))

        Response taracallback = Requests.getRequestWithParams(flow, flow.sessionService.fullTaraCallbackUrl, paramsMap)

        assertThat("Correct HTTP status code", taracallback.statusCode, is(400))
        assertThat("Correct error", taracallback.body.jsonPath().getString("error"), is("USER_COOKIE_MISSING"))
        assertThat("Correct error message", taracallback.body.jsonPath().getString("message"), is("Küpsis on puudu või kehtivuse kaotanud"))
    }

    @Feature("SECURE_COOKIE_HANDLING")
    @Feature("LOGIN_TARACALLBACK_ENDPOINT")
    def "Taracallback request with incorrect __Host-AUTH cookie"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)

        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookieMap, "__Host-AUTH", "incorrect")

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "state", Utils.getParamValueFromResponseHeader(taraAuthentication, "state"))
        Utils.setParameter(paramsMap, "code", Utils.getParamValueFromResponseHeader(taraAuthentication, "code"))

        Response taracallback = Requests.getRequestWithCookiesAndParams(flow, flow.sessionService.fullTaraCallbackUrl, cookieMap, paramsMap)

        assertThat("Correct HTTP status code", taracallback.statusCode, is(400))
        assertThat("Correct error", taracallback.body.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct error message", taracallback.body.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGIN_REJECT_ENDPOINT")
    @Feature("LOGIN_TARACALLBACK_ENDPOINT")
    def "Correct redirect URL is returned from TARA after 'back to service provider' request"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraOidcAuth1 = Steps.followRedirect(flow, initLogin)
        Response tarainitLogin = Steps.followRedirect(flow, taraOidcAuth1)

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "error_code", REJECT_ERROR_CODE)
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookieMap, "__Host-SESSION", tarainitLogin.getCookie("__Host-SESSION"))
        Response taraReject = Requests.getRequestWithCookiesAndParams(flow, flow.taraService.fullAuthRejectUrl, cookieMap, paramsMap)

        Response taraOidcAuth2 = Steps.followRedirect(flow, taraReject)

        assertThat("Correct redirect URL", taraOidcAuth2.getHeader("location").startsWith(flow.sessionService.fullTaraCallbackUrl))
        assertThat("Correct error in URL", taraOidcAuth2.getHeader("location").contains("error=user_cancel"))
        assertThat("Correct error description in URL", taraOidcAuth2.getHeader("location").contains("error_description=User+canceled+the+authentication+process."))
        assertThat("URL contains state parameter", taraOidcAuth2.getHeader("location").contains("state"))
    }

    @Unroll
    @Feature("CONSENT_INIT_ENDPOINT")
    def "Incorrect consent challenge: #reason"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, paramKey, paramValue)

        Response initConsent = Requests.getRequestWithParams(flow, flow.sessionService.fullConsentUrl, paramsMap)

        assertThat("Correct HTTP status code", initConsent.statusCode, is(status))
        assertThat("Correct error", initConsent.jsonPath().getString("error"), is(error))
        assertThat("Correct message", initConsent.jsonPath().getString("message"), is(errorMessage))

        where:
        reason                | paramKey            | paramValue | status | error        | errorMessage
        "Empty value"         | "consent_challenge" | ""         | 400    | "USER_INPUT" | "Ebakorrektne päring."
        "Illegal characters"  | "consent_challenge" | "123_!?#"  | 400    | "USER_INPUT" | "Ebakorrektne päring."
        "Missing parameter"   | ""                  | ""         | 400    | "USER_INPUT" | "Ebakorrektne päring."
        "Incorrect parameter" | "consent_"          | "a" * 32   | 400    | "USER_INPUT" | "Ebakorrektne päring."
        "Not matching value"  | "consent_challenge" | "a" * 32   | 400    | "USER_INPUT" | "Ebakorrektne päring."
        "Over maxLength"      | "consent_challenge" | "a" * 33   | 400    | "USER_INPUT" | "Ebakorrektne päring."
        "Under minLength"     | "consent_challenge" | "a" * 31   | 400    | "USER_INPUT" | "Ebakorrektne päring."
    }

    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Continue session request without existing session"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Response initLogin = Steps.followRedirect(flow, oidcAuth)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", flow.loginChallenge.toString())
        Utils.setParameter(formParams, "_csrf", initLogin.cookies.get("__Host-XSRF-TOKEN"))

        Response continueSession = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies, formParams)

        assertThat("Correct HTTP status code", continueSession.statusCode, is(400))
        assertThat("Correct error", continueSession.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", continueSession.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("SECURE_COOKIE_HANDLING")
    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Continue session with invalid __Host-XSRF-TOKEN cookie"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcAuth)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", flow.loginChallenge.toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.cookies.get("__Host-XSRF-TOKEN"))

        Utils.setParameter(flow.sessionService.cookies, "__Host-XSRF-TOKEN", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        Response continueSession = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies, formParams)

        assertThat("Correct HTTP status code", continueSession.statusCode, is(403))
        assertThat("Correct error", continueSession.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", continueSession.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Continue session with invalid _csrf form parameter"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcAuth)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", flow.loginChallenge.toString())
        Utils.setParameter(formParams, "_csrf", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

        Response continueSession = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies, formParams)

        assertThat("Correct HTTP status code", continueSession.statusCode, is(403))
        assertThat("Correct error", continueSession.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", continueSession.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Continue session with invalid loginChallenge form parameter"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcAuth)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", "0a0aaaa00aa00a00000aa0a0000000aa")
        Utils.setParameter(formParams, "_csrf", flow.sessionService.cookies.get("__Host-XSRF-TOKEN"))

        Response continueSession = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies, formParams)

        assertThat("Correct HTTP status code", continueSession.statusCode, is(400))
        assertThat("Correct error", continueSession.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", continueSession.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("SECURE_COOKIE_HANDLING")
    @Feature("LOGIN_REAUTHENTICATE_ENDPOINT")
    def "Reauthenticate with invalid __Host-XSRF-TOKEN cookie"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcAuth)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", flow.loginChallenge.toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.cookies.get("__Host-XSRF-TOKEN"))

        Utils.setParameter(flow.sessionService.cookies, "__Host-XSRF-TOKEN", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        Response reauthenticateWithExistingSession = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullReauthenticateUrl, flow.sessionService.cookies, formParams)

        assertThat("Correct HTTP status code", reauthenticateWithExistingSession.statusCode, is(403))
        assertThat("Correct error", reauthenticateWithExistingSession.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", reauthenticateWithExistingSession.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGIN_REAUTHENTICATE_ENDPOINT")
    def "Reauthenticate with invalid _csrf form parameter"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcAuth)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", flow.loginChallenge.toString())
        Utils.setParameter(formParams, "_csrf", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

        Response reauthenticateWithExistingSession = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullReauthenticateUrl, flow.sessionService.cookies, formParams)

        assertThat("Correct HTTP status code", reauthenticateWithExistingSession.statusCode, is(403))
        assertThat("Correct error", reauthenticateWithExistingSession.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", reauthenticateWithExistingSession.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGIN_REAUTHENTICATE_ENDPOINT")
    def "Reauthenticate with invalid loginChallenge form parameter"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcAuth)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", "0a0aaaa00aa00a00000aa0a0000000aa")
        Utils.setParameter(formParams, "_csrf", flow.sessionService.cookies.get("__Host-XSRF-TOKEN"))

        Response reauthenticateWithExistingSession = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullReauthenticateUrl, flow.sessionService.cookies, formParams)

        assertThat("Correct HTTP status code", reauthenticateWithExistingSession.statusCode, is(400))
        assertThat("Correct error", reauthenticateWithExistingSession.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", reauthenticateWithExistingSession.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Continue session without existing session"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow)
        Steps.followRedirect(flow, oidcAuth)
        Response continueSession = Requests.postRequestWithCookies(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies)

        assertThat("Correct HTTP status code", continueSession.statusCode, is(403))
        assertThat("Correct error", continueSession.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", continueSession.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGIN_REAUTHENTICATE_ENDPOINT")
    def "Reauthenticate without existing session"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow)
        Steps.followRedirect(flow, oidcAuth)
        Response reauthenticate = Requests.postRequestWithCookies(flow, flow.sessionService.fullReauthenticateUrl, flow.sessionService.cookies)

        assertThat("Correct HTTP status code", reauthenticate.statusCode, is(403))
        assertThat("Correct error", reauthenticate.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", reauthenticate.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("BUSINESS_LOGIC")
    @Feature("LOGIN_INIT_ENDPOINT")
    def "Create session in client-A with eIDAS substantial acr and initialize authentication sequence in client-B with high acr"() {
        expect:
        Response createSession = Steps.authenticateWithEidasInGovSso(flow, "substantial", "C")
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, createSession.body.jsonPath().get("id_token")).getJWTClaimsSet()

        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Response initLogin = Steps.followRedirect(flow, oidcAuth)

        assertThat("Correct HTTP status code", initLogin.statusCode, is(200))
        assertThat("Correct acr value in token", claims.getClaim("acr"), is("substantial"))
    }

    @Feature("LOGOUT_CONTINUE_SESSION_ENDPOINT")
    def "Log out with continue session without _csrf form parameter"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.jsonPath().get("id_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, flow.oidcClientB.fullBaseUrl)
        Steps.followRedirect(flow, oidcLogout)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "logoutChallenge", flow.logoutChallenge.toString())

        Response logoutContinueSession = Requests.postRequestWithParams(flow, flow.sessionService.fullLogoutContinueSessionUrl, formParams)

        assertThat("Correct HTTP status code", logoutContinueSession.statusCode, is(403))
        assertThat("Correct error", logoutContinueSession.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", logoutContinueSession.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGOUT_CONTINUE_SESSION_ENDPOINT")
    def "Log out with continue session without logoutChallenge form parameter"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.jsonPath().get("id_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, flow.oidcClientB.fullBaseUrl)
        Steps.followRedirect(flow, oidcLogout)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "_csrf", flow.sessionService.cookies.get("__Host-XSRF-TOKEN"))

        Response logoutContinueSession = Requests.postRequestWithParams(flow, flow.sessionService.fullLogoutContinueSessionUrl, formParams)

        assertThat("Correct HTTP status code", logoutContinueSession.statusCode, is(400))
        assertThat("Correct error", logoutContinueSession.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", logoutContinueSession.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGOUT_CONTINUE_SESSION_ENDPOINT")
    def "Log out with continue session with invalid _csrf form parameter"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.jsonPath().get("id_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, flow.oidcClientB.fullBaseUrl)
        Steps.followRedirect(flow, oidcLogout)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "logoutChallenge", flow.logoutChallenge.toString())
        Utils.setParameter(formParams, "_csrf", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

        Response logoutContinueSession = Requests.postRequestWithParams(flow, flow.sessionService.fullLogoutContinueSessionUrl, formParams)

        assertThat("Correct HTTP status code", logoutContinueSession.statusCode, is(403))
        assertThat("Correct error", logoutContinueSession.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", logoutContinueSession.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGOUT_CONTINUE_SESSION_ENDPOINT")
    def "Log out with continue session with invalid logoutChallenge form parameter"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.jsonPath().get("id_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, flow.oidcClientB.fullBaseUrl)
        Steps.followRedirect(flow, oidcLogout)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "logoutChallenge", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        Utils.setParameter(formParams, "_csrf", flow.sessionService.cookies.get("__Host-XSRF-TOKEN"))

        Response logoutContinueSession = Requests.postRequestWithParams(flow, flow.sessionService.fullLogoutContinueSessionUrl, formParams)

        assertThat("Correct HTTP status code", logoutContinueSession.statusCode, is(400))
        assertThat("Correct error", logoutContinueSession.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", logoutContinueSession.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("SECURE_COOKIE_HANDLING")
    @Feature("LOGOUT_CONTINUE_SESSION_ENDPOINT")
    def "Log out with continue session with incorrect __Host-XSRF-TOKEN cookie"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.jsonPath().get("id_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, flow.oidcClientB.fullBaseUrl)
        Steps.followRedirect(flow, oidcLogout)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "logoutChallenge", flow.logoutChallenge.toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.cookies.get("__Host-XSRF-TOKEN"))

        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookieMap, "__Host-XSRF-TOKEN", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        Response logoutContinueSession = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullLogoutContinueSessionUrl, cookieMap, formParams)

        assertThat("Correct HTTP status code", logoutContinueSession.statusCode, is(403))
        assertThat("Correct error", logoutContinueSession.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", logoutContinueSession.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGOUT_END_SESSION_ENDPOINT")
    def "Log out with end session without _csrf form parameter"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.jsonPath().get("id_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, flow.oidcClientB.fullBaseUrl)
        Steps.followRedirect(flow, oidcLogout)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "logoutChallenge", flow.logoutChallenge.toString())

        Response logoutContinueSession = Requests.postRequestWithParams(flow, flow.sessionService.fullLogoutEndSessionUrl, formParams)

        assertThat("Correct HTTP status code", logoutContinueSession.statusCode, is(403))
        assertThat("Correct error", logoutContinueSession.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", logoutContinueSession.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGOUT_END_SESSION_ENDPOINT")
    def "Log out with end session without logoutChallenge form parameter"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.jsonPath().get("id_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, flow.oidcClientB.fullBaseUrl)
        Steps.followRedirect(flow, oidcLogout)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "_csrf", flow.sessionService.cookies.get("__Host-XSRF-TOKEN"))

        Response logoutContinueSession = Requests.postRequestWithParams(flow, flow.sessionService.fullLogoutEndSessionUrl, formParams)

        assertThat("Correct HTTP status code", logoutContinueSession.statusCode, is(400))
        assertThat("Correct error", logoutContinueSession.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", logoutContinueSession.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGOUT_END_SESSION_ENDPOINT")
    def "Log out with end session with invalid _csrf form parameter"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.jsonPath().get("id_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, flow.oidcClientB.fullBaseUrl)
        Steps.followRedirect(flow, oidcLogout)
        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "logoutChallenge", flow.logoutChallenge.toString())
        Utils.setParameter(formParams, "_csrf", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        Response logoutContinueSession = Requests.postRequestWithParams(flow, flow.sessionService.fullLogoutEndSessionUrl, formParams)

        assertThat("Correct HTTP status code", logoutContinueSession.statusCode, is(403))
        assertThat("Correct error", logoutContinueSession.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", logoutContinueSession.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGOUT_END_SESSION_ENDPOINT")
    def "Log out with end session with invalid logoutChallenge form parameter"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.jsonPath().get("id_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, flow.oidcClientB.fullBaseUrl)
        Steps.followRedirect(flow, oidcLogout)
        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "logoutChallenge", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        Utils.setParameter(formParams, "_csrf", flow.sessionService.cookies.get("__Host-XSRF-TOKEN"))
        Response logoutContinueSession = Requests.postRequestWithParams(flow, flow.sessionService.fullLogoutEndSessionUrl, formParams)

        assertThat("Correct HTTP status code", logoutContinueSession.statusCode, is(400))
        assertThat("Correct error", logoutContinueSession.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", logoutContinueSession.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("SECURE_COOKIE_HANDLING")
    @Feature("LOGOUT_END_SESSION_ENDPOINT")
    def "Log out with end session with incorrect __Host-XSRF-TOKEN cookie"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.jsonPath().get("id_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, flow.oidcClientB.fullBaseUrl)
        Steps.followRedirect(flow, oidcLogout)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "logoutChallenge", flow.logoutChallenge.toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.cookies.get("__Host-XSRF-TOKEN"))

        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookieMap, "__Host-XSRF-TOKEN", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

        Response logoutContinueSession = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullLogoutEndSessionUrl, cookieMap, formParams)

        assertThat("Correct HTTP status code", logoutContinueSession.statusCode, is(403))
        assertThat("Correct error", logoutContinueSession.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", logoutContinueSession.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGOUT_INIT_ENDPOINT")
    def "Log out request for client-B with incorrect logout_challenge query parameter"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.jsonPath().get("id_token")

        HashMap<String, String> queryParamsOidc = new HashMap<>()
        Utils.setParameter(queryParamsOidc, "id_token_hint", idToken)
        Utils.setParameter(queryParamsOidc, "post_logout_redirect_uri", flow.oidcClientB.fullBaseUrl)

        Requests.getRequestWithParams(flow, flow.ssoOidcService.fullLogoutUrl, queryParamsOidc)

        HashMap<String, String> queryParamsSession = new HashMap<>()
        Utils.setParameter(queryParamsSession, "logout_challenge", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

        Response initLogout = Requests.getRequestWithParams(flow, flow.sessionService.fullLogoutInitUrl, queryParamsSession)

        assertThat("Correct HTTP status code", initLogout.statusCode, is(400))
        assertThat("Correct error", initLogout.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", initLogout.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGOUT_INIT_ENDPOINT")
    def "Log out request with empty post_logout_redirect_uri parameter value"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.jsonPath().get("id_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, "")
        Response initLogout = Steps.followRedirect(flow, oidcLogout)

        assertThat("Correct HTTP status code", initLogout.statusCode, is(400))
        assertThat("Correct error", initLogout.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", initLogout.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGOUT_INIT_ENDPOINT")
    def "Log out request with missing post_logout_redirect_uri parameter"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.jsonPath().get("id_token")

        HashMap<String, String> queryParamas = new HashMap<>()
        Utils.setParameter(queryParamas, "id_token_hint", idToken)
        Response oidcLogout = Requests.getRequestWithParams(flow, flow.ssoOidcService.fullLogoutUrl, queryParamas)

        flow.setLogoutChallenge(Utils.getParamValueFromResponseHeader(oidcLogout, "logout_challenge"))

        Response initLogout = Steps.followRedirect(flow, oidcLogout)

        assertThat("Correct HTTP status code", initLogout.statusCode, is(400))
        assertThat("Correct error", initLogout.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", initLogout.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGIN_REJECT_ENDPOINT")
    def "Login reject request with missing loginChallenge form parameter"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcAuth)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "_csrf", flow.sessionService.cookies.get("__Host-XSRF-TOKEN"))
        Response loginReject = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullLoginRejectUrl, flow.sessionService.cookies, formParams)

        assertThat("Correct HTTP status code", loginReject.statusCode, is(400))
        assertThat("Correct error", loginReject.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", loginReject.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }

    @Feature("LOGIN_REJECT_ENDPOINT")
    def "Login reject request with missing _csrf form parameter"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcAuth)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", flow.loginChallenge.toString())
        Response loginReject = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullLoginRejectUrl, flow.sessionService.cookies, formParams)

        assertThat("Correct HTTP status code", loginReject.statusCode, is(403))
        assertThat("Correct error", loginReject.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct message", loginReject.jsonPath().getString("message"), is("Ebakorrektne päring."))
    }
}
