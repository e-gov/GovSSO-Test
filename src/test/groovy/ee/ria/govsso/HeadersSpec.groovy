package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.junit.jupiter.api.Assertions.assertEquals
import static org.junit.jupiter.api.Assertions.assertTrue

class HeadersSpec extends GovSsoSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Feature("CORS")
    def "Cross-Origin Resource Sharing headers are applied correctly in session refresh request sequence"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovsso(flow)
        String idToken = createSession.jsonPath().get("id_token")

        Response oidcRefreshSession = Steps.startSessionRefreshInSsoOidcWithDefaults(flow, idToken, flow.oidcClientA.fullBaseUrl)
        Response initLogin = Steps.followRedirectWithOrigin(flow, oidcRefreshSession, flow.oidcClientA.fullBaseUrl)
        Response loginVerifier = Steps.followRedirectWithCookiesAndOrigin(flow, initLogin, flow.ssoOidcService.cookies, flow.oidcClientA.fullBaseUrl)
        Response initConsent = Steps.followRedirectWithOrigin(flow, loginVerifier, flow.oidcClientA.fullBaseUrl)
        Response consentVerifier = Steps.followRedirectWithCookiesAndOrigin(flow, initConsent, flow.ssoOidcService.cookies, flow.oidcClientA.fullBaseUrl)

        assertEquals("true", oidcRefreshSession.getHeader("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is present and has correct value")
        assertEquals((flow.oidcClientA.fullBaseUrl).toString(), oidcRefreshSession.getHeader("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is present and has correct value")

        assertEquals("true", initLogin.getHeader("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is present and has correct value")
        assertEquals((flow.oidcClientA.fullBaseUrl).toString(), initLogin.getHeader("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is present and has correct value")

        assertEquals("true", loginVerifier.getHeader("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is present and has correct value")
        assertEquals((flow.oidcClientA.fullBaseUrl).toString(), loginVerifier.getHeader("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is present and has correct value")

        assertEquals("true", initConsent.getHeader("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is present and has correct value")
        assertEquals((flow.oidcClientA.fullBaseUrl).toString(), initConsent.getHeader("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is present and has correct value")

        assertEquals("true", consentVerifier.getHeader("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is present and has correct value")
        assertEquals((flow.oidcClientA.fullBaseUrl).toString(), consentVerifier.getHeader("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is present and has correct value")
    }

    @Feature("CORS")
    def "Cross-Origin Resource Sharing headers are not applied in login request sequence"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParamsAndOrigin(flow, paramsMap, flow.oidcClientA.fullBaseUrl)
        Response initLogin = Steps.startSessionInSessionServiceWithOrigin(flow, oidcAuth, flow.oidcClientA.fullBaseUrl)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response taracallback = Steps.followRedirectWithCookiesAndOrigin(flow, taraAuthentication, flow.sessionService.cookies, flow.oidcClientA.fullBaseUrl)
        Response loginVerifier = Steps.followRedirectWithCookiesAndOrigin(flow, taracallback, flow.ssoOidcService.cookies, flow.oidcClientA.fullBaseUrl)
        Response initConsent = Steps.followRedirectWithOrigin(flow, loginVerifier, flow.oidcClientA.fullBaseUrl)
        Response consentVerifier = Steps.followRedirectWithCookiesAndOrigin(flow, initConsent, flow.ssoOidcService.cookies, flow.oidcClientA.fullBaseUrl)

        assertTrue(!oidcAuth.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in login request sequence")
        assertTrue(!oidcAuth.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in login request sequence")

        assertTrue(!taracallback.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in login request sequence")
        assertTrue(!taracallback.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in login request sequence")

        assertTrue(!loginVerifier.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in login request sequence")
        assertTrue(!loginVerifier.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in login request sequence")

        assertTrue(!consentVerifier.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in login request sequence")
        assertTrue(!consentVerifier.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in login request sequence")
    }

    @Feature("CORS")
    def "Cross-Origin Resource Sharing headers are not applied in session continuation request sequence"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithOrigin(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl, flow.oidcClientB.fullBaseUrl)
        Steps.followRedirectWithOrigin(flow, oidcAuth, flow.oidcClientB.fullBaseUrl)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", flow.getLoginChallenge().toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))
        Response continueSession = Requests.postRequestWithCookiesParamsAndOrigin(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies, formParams, flow.oidcClientB.fullBaseUrl)

        Response loginVerifier = Steps.followRedirectWithCookiesAndOrigin(flow, continueSession, flow.ssoOidcService.cookies, flow.oidcClientA.fullBaseUrl)
        Response initConsent = Steps.followRedirectWithOrigin(flow, loginVerifier, flow.oidcClientB.fullBaseUrl)
        Response consentVerifier = Steps.followRedirectWithCookiesAndOrigin(flow, initConsent, flow.ssoOidcService.cookies, flow.oidcClientA.fullBaseUrl)

        assertTrue(!oidcAuth.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in session continuation request sequence")
        assertTrue(!oidcAuth.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in session continuation request sequence")

        assertTrue(!continueSession.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in session continuation request sequence")
        assertTrue(!continueSession.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in session continuation request sequence")

        assertTrue(!loginVerifier.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in session continuation request sequence")
        assertTrue(!loginVerifier.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in session continuation request sequence")

        assertTrue(!consentVerifier.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in session continuation request sequence")
        assertTrue(!consentVerifier.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in session continuation request sequence")
    }

    @Feature("CORS")
    def "Cross-Origin Resource Sharing headers are not applied in logout with session continuation request sequence"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueSession.jsonPath().get("id_token")

        Response oidcLogout = Steps.startLogoutWithOrigin(flow, idToken, flow.oidcClientB.fullBaseUrl, flow.oidcClientB.fullBaseUrl)
        Response initLogout = Steps.followRedirectWithOrigin(flow, oidcLogout, flow.oidcClientA.fullBaseUrl)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "logoutChallenge", flow.getLogoutChallenge().toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))
        Response logoutContinueSession = Requests.postRequestWithCookiesParamsAndOrigin(flow, flow.sessionService.fullLogoutContinueSessionUrl, Collections.emptyMap(), formParams, flow.oidcClientB.fullBaseUrl)

        assertTrue(!oidcLogout.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in logout with session continuation request sequence")
        assertTrue(!oidcLogout.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in logout with session continuation request sequence")

        assertTrue(!initLogout.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in logout with session continuation request sequence")
        assertTrue(!initLogout.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in logout with session continuation request sequence")

        assertTrue(!logoutContinueSession.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in logout with session continuation request sequence")
        assertTrue(!logoutContinueSession.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in logout with session continuation request sequence")
    }

    @Feature("CORS")
    def "Cross-Origin Resource Sharing headers are not applied in logout with end session request sequence"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueSession.jsonPath().get("id_token")

        Response oidcLogout = Steps.startLogoutWithOrigin(flow, idToken, flow.oidcClientB.fullBaseUrl, flow.oidcClientB.fullBaseUrl)
        Steps.followRedirectWithOrigin(flow, oidcLogout, flow.oidcClientA.fullBaseUrl)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "logoutChallenge", flow.getLogoutChallenge().toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))
        Response logoutEndSession = Requests.postRequestWithCookiesParamsAndOrigin(flow, flow.sessionService.fullLogoutEndSessionUrl, Collections.emptyMap(), formParams, flow.oidcClientB.fullBaseUrl)

        assertTrue(!logoutEndSession.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in logout with end session request sequence")
        assertTrue(!logoutEndSession.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in logout with end session request sequence")
    }

    @Feature("CORS")
    def "Cross-Origin Resource Sharing headers are not applied in error request"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "invalid-client-id", flow.oidcClientA.fullResponseUrl)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response oidcError = Steps.followRedirectWithOrigin(flow, oidcAuth, flow.oidcClientA.fullBaseUrl)

        assertTrue(!oidcError.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in oidc error request")
        assertTrue(!oidcError.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in oidc error request")
    }

    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("DISALLOW_IFRAMES")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify response headers for session service requests in login sequence"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response taracallback = Steps.followRedirectWithCookies(flow, taraAuthentication, flow.sessionService.cookies)
        Response loginVerifier = Steps.followRedirectWithCookies(flow, taracallback, flow.ssoOidcService.cookies)
        Response initConsent = Steps.followRedirect(flow, loginVerifier)

        Steps.verifyResponseHeaders(initLogin)
        Steps.verifyResponseHeaders(taracallback)
        Steps.verifyResponseHeaders(initConsent)
    }

    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("DISALLOW_IFRAMES")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify response headers for session service requests in session refresh sequence"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovsso(flow)
        String idToken = createSession.jsonPath().get("id_token")

        Response oidcRefreshSession = Steps.startSessionRefreshInSsoOidcWithDefaults(flow, idToken, flow.oidcClientA.fullBaseUrl)
        Response initLogin = Steps.followRedirect(flow, oidcRefreshSession)
        Response loginVerifier = Steps.followRedirectWithCookies(flow, initLogin, flow.ssoOidcService.cookies)
        Response initConsent = Steps.followRedirect(flow, loginVerifier)

        Steps.verifyResponseHeaders(initLogin)
        Steps.verifyResponseHeaders(initConsent)
        Steps.verifyResponseHeaders(initLogin)
    }

    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("DISALLOW_IFRAMES")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify response headers for session service requests in session continuation sequence"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Response initLogin = Steps.followRedirect(flow, oidcAuth)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", Utils.getParamValueFromResponseHeader(oidcAuth, "login_challenge"))
        Utils.setParameter(formParams, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))
        Response continueSession = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies, formParams)

        Response loginVerifier = Steps.followRedirectWithCookies(flow, continueSession, flow.ssoOidcService.cookies)
        Response initConsent = Steps.followRedirect(flow, loginVerifier)

        Steps.verifyResponseHeaders(initLogin)
        Steps.verifyResponseHeaders(continueSession)
        Steps.verifyResponseHeaders(initConsent)
    }

    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("DISALLOW_IFRAMES")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify response headers for session service requests in reauthentication sequence"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcAuth)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", Utils.getParamValueFromResponseHeader(oidcAuth, "login_challenge"))
        Utils.setParameter(formParams, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))
        Response reauthenticate = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullReauthenticateUrl, flow.sessionService.cookies, formParams)

        Steps.verifyResponseHeaders(reauthenticate)
    }

    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("DISALLOW_IFRAMES")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify response headers for session service requests in logout with session end sequence"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueSession.jsonPath().get("id_token")

        Response logoutEndSession = Steps.logout(flow, idToken, flow.oidcClientB.fullBaseUrl, flow.sessionService.fullLogoutEndSessionUrl)

        Steps.verifyResponseHeaders(logoutEndSession)
    }

    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("DISALLOW_IFRAMES")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify response headers for session service requests in logout with session continuation sequence"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueSession.jsonPath().get("id_token")

        Response logoutContinueSession = Steps.logout(flow, idToken, flow.oidcClientB.fullBaseUrl, flow.sessionService.fullLogoutContinueSessionUrl)

        Steps.verifyResponseHeaders(logoutContinueSession)
    }
}