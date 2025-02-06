package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.hamcrest.MatcherAssert.assertThat

class HeadersSpec extends GovSsoSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Feature("CORS")
    def "Cross-Origin Resource Sharing headers are not applied in login request sequence"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParamsAndOrigin(flow, paramsMap, flow.oidcClientA.fullBaseUrl)
        Response initLogin = Steps.startSessionInSessionServiceWithOrigin(flow, oidcAuth, flow.oidcClientA.fullBaseUrl)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response taracallback = Steps.followRedirectWithOrigin(flow, taraAuthentication, flow.oidcClientA.fullBaseUrl)
        Response loginVerifier = Steps.followRedirectWithOrigin(flow, taracallback, flow.oidcClientA.fullBaseUrl)
        Response initConsent = Steps.followRedirectWithOrigin(flow, loginVerifier, flow.oidcClientA.fullBaseUrl)
        Response consentVerifier = Steps.followRedirectWithOrigin(flow, initConsent, flow.oidcClientA.fullBaseUrl)

        assertThat("Access-Control-Allow-Credentials header is not present in login request sequence", !oidcAuth.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"))
        assertThat("Access-Control-Allow-Origin header is not present in login request sequence", !oidcAuth.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"))

        assertThat("Access-Control-Allow-Credentials header is not present in login request sequence", !taracallback.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"))
        assertThat("Access-Control-Allow-Origin header is not present in login request sequence", !taracallback.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"))

        assertThat("Access-Control-Allow-Credentials header is not present in login request sequence", !loginVerifier.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"))
        assertThat("Access-Control-Allow-Origin header is not present in login request sequence", !loginVerifier.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"))

        assertThat("Access-Control-Allow-Credentials header is not present in login request sequence", !consentVerifier.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"))
        assertThat("Access-Control-Allow-Origin header is not present in login request sequence", !consentVerifier.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"))
    }

    @Feature("CORS")
    def "Cross-Origin Resource Sharing headers are not applied in session continuation request sequence"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithOrigin(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl, flow.oidcClientB.fullBaseUrl)
        Response initLogin = Steps.followRedirectWithOrigin(flow, oidcAuth, flow.oidcClientB.fullBaseUrl)

        Map formParams = [loginChallenge: flow.loginChallenge,
                          _csrf         : initLogin.htmlPath().get("**.find {it.@name == '_csrf'}.@value")]
        Response continueSession = Requests.postRequestWithParamsAndOrigin(flow, flow.sessionService.fullContinueSessionUrl, formParams, flow.oidcClientB.fullBaseUrl)

        Response loginVerifier = Steps.followRedirectWithOrigin(flow, continueSession, flow.oidcClientA.fullBaseUrl)
        Response initConsent = Steps.followRedirectWithOrigin(flow, loginVerifier, flow.oidcClientB.fullBaseUrl)
        Response consentVerifier = Steps.followRedirectWithOrigin(flow, initConsent, flow.oidcClientA.fullBaseUrl)

        assertThat("Access-Control-Allow-Credentials header is not present in session continuation request sequence", !oidcAuth.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"))
        assertThat("Access-Control-Allow-Origin header is not present in session continuation request sequence", !oidcAuth.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"))

        assertThat("Access-Control-Allow-Credentials header is not present in session continuation request sequence", !continueSession.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"))
        assertThat("Access-Control-Allow-Origin header is not present in session continuation request sequence", !continueSession.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"))

        assertThat("Access-Control-Allow-Credentials header is not present in session continuation request sequence", !loginVerifier.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"))
        assertThat("Access-Control-Allow-Origin header is not present in session continuation request sequence", !loginVerifier.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"))

        assertThat("Access-Control-Allow-Credentials header is not present in session continuation request sequence", !consentVerifier.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"))
        assertThat("Access-Control-Allow-Origin header is not present in session continuation request sequence", !consentVerifier.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"))
    }

    @Feature("CORS")
    def "Cross-Origin Resource Sharing headers are not applied in logout with session continuation request sequence"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.path("id_token")

        Response oidcLogout = Steps.startLogoutWithOrigin(flow, idToken, flow.oidcClientB.fullBaseUrl, flow.oidcClientB.fullBaseUrl)
        Response initLogout = Steps.followRedirectWithOrigin(flow, oidcLogout, flow.oidcClientA.fullBaseUrl)

        Map formParams = [logoutChallenge: flow.logoutChallenge,
                          _csrf          : flow.sessionService.getCookies().get("__Host-XSRF-TOKEN")]
        Response logoutContinueSession = Requests.postRequestWithParamsAndOrigin(flow, flow.sessionService.fullLogoutContinueSessionUrl, formParams, flow.oidcClientB.fullBaseUrl)

        assertThat("Access-Control-Allow-Credentials header is not present in logout with session continuation request sequence", !oidcLogout.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"))
        assertThat("Access-Control-Allow-Origin header is not present in logout with session continuation request sequence", !oidcLogout.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"))

        assertThat("Access-Control-Allow-Credentials header is not present in logout with session continuation request sequence", !initLogout.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"))
        assertThat("Access-Control-Allow-Origin header is not present in logout with session continuation request sequence", !initLogout.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"))

        assertThat("Access-Control-Allow-Credentials header is not present in logout with session continuation request sequence", !logoutContinueSession.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"))
        assertThat("Access-Control-Allow-Origin header is not present in logout with session continuation request sequence", !logoutContinueSession.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"))
    }

    @Feature("CORS")
    def "Cross-Origin Resource Sharing headers are not applied in logout with end session request sequence"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.path("id_token")

        Response oidcLogout = Steps.startLogoutWithOrigin(flow, idToken, flow.oidcClientB.fullBaseUrl, flow.oidcClientB.fullBaseUrl)
        Steps.followRedirectWithOrigin(flow, oidcLogout, flow.oidcClientA.fullBaseUrl)

        Map formParams = [logoutChallenge: flow.logoutChallenge,
                          _csrf          : flow.sessionService.getCookies().get("__Host-XSRF-TOKEN")]
        Response logoutEndSession = Requests.postRequestWithParamsAndOrigin(flow, flow.sessionService.fullLogoutEndSessionUrl, formParams, flow.oidcClientB.fullBaseUrl)

        assertThat("Access-Control-Allow-Credentials header is not present in logout with end session request sequence", !logoutEndSession.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"))
        assertThat("Access-Control-Allow-Origin header is not present in logout with end session request sequence", !logoutEndSession.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"))
    }

    @Feature("CORS")
    def "Cross-Origin Resource Sharing headers are not applied in error request"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "invalid-client-id", flow.oidcClientA.fullResponseUrl)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response oidcError = Steps.followRedirectWithOrigin(flow, oidcAuth, flow.oidcClientA.fullBaseUrl)

        assertThat("Access-Control-Allow-Credentials header is not present in oidc error request", !oidcError.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"))
        assertThat("Access-Control-Allow-Origin header is not present in oidc error request", !oidcError.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"))
    }

    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("DISALLOW_IFRAMES")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify response headers for session service requests in login sequence"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response taracallback = Steps.followRedirect(flow, taraAuthentication)
        Response loginVerifier = Steps.followRedirect(flow, taracallback)
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
    def "Verify response headers for session service requests in session continuation sequence"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Response initLogin = Steps.followRedirect(flow, oidcAuth)

        Map formParams = [loginChallenge: Utils.getParamValueFromResponseHeader(oidcAuth, "login_challenge"),
                          _csrf         : initLogin.htmlPath().get("**.find {it.@name == '_csrf'}.@value")]

        Response continueSession = Requests.postRequestWithParams(flow, flow.sessionService.fullContinueSessionUrl, formParams)

        Response loginVerifier = Steps.followRedirect(flow, continueSession)
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
        Steps.authenticateWithIdCardInGovSso(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcAuth)

        Map formParams = [loginChallenge: Utils.getParamValueFromResponseHeader(oidcAuth, "login_challenge"),
                          _csrf         : flow.sessionService.getCookies().get("__Host-XSRF-TOKEN")]

        Response reauthenticate = Requests.postRequestWithParams(flow, flow.sessionService.fullReauthenticateUrl, formParams)

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
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.path("id_token")

        Response logoutEndSession = Steps.logout(flow, idToken, flow.oidcClientB.fullLogoutRedirectUrl, flow.sessionService.fullLogoutEndSessionUrl)

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
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.path("id_token")

        Response logoutContinueSession = Steps.logout(flow, idToken, flow.oidcClientB.fullLogoutRedirectUrl, flow.sessionService.fullLogoutContinueSessionUrl)

        Steps.verifyResponseHeaders(logoutContinueSession)
    }
}
