package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.junit.jupiter.api.Assertions.assertEquals
import static org.junit.jupiter.api.Assertions.assertTrue

class CorsSpec extends GovSsoSpecification {

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

        Response initRefreshSession = Steps.startSessionRefreshInSsoOidcWithOrigin(flow, idToken, flow.oidcClientA.fullBaseUrl)
        Response initLogin = Steps.followRedirectWithOrigin(flow, initRefreshSession, flow.oidcClientA.fullBaseUrl)
        Response loginVerifier = Steps.followRedirectWithOrigin(flow, initLogin, flow.oidcClientA.fullBaseUrl)
        Response initConsent = Steps.followRedirectWithOrigin(flow, loginVerifier, flow.oidcClientA.fullBaseUrl)
        Response consentVerifier = Steps.followRedirectWithOrigin(flow, initConsent, flow.oidcClientA.fullBaseUrl)

        assertEquals("true", initRefreshSession.getHeader("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is present and has correct value")
        assertEquals((flow.oidcClientA.fullBaseUrl).toString(), initRefreshSession.getHeader("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is present and has correct value")

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
        Response loginInit = Steps.startSessionInSessionServiceWithOrigin(flow, oidcAuth, flow.oidcClientA.fullBaseUrl)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, loginInit)
        Response taracallback = Steps.followRedirectWithCookiesAndOrigin(flow, taraAuthentication, flow.sessionService.cookies, flow.oidcClientA.fullBaseUrl)
        Response loginVerifier = Steps.followRedirectWithOrigin(flow, taracallback, flow.oidcClientA.fullBaseUrl)
        Response initConsent = Steps.followRedirectWithOrigin(flow, loginVerifier, flow.oidcClientA.fullBaseUrl)
        Response consentVerifier = Steps.followRedirectWithOrigin(flow, initConsent, flow.oidcClientA.fullBaseUrl)


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

        Response loginVerifier = Steps.followRedirectWithOrigin(flow, continueSession, flow.oidcClientB.fullBaseUrl)
        Response initConsent = Steps.followRedirectWithOrigin(flow, loginVerifier, flow.oidcClientB.fullBaseUrl)
        Response consentVerifier = Steps.followRedirectWithOrigin(flow, initConsent, flow.oidcClientB.fullBaseUrl)


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
}