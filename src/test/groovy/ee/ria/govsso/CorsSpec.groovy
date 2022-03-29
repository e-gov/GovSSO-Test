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

    @Feature("AUTHENTICATION")
    def "Cross-Origin Resource Sharing headers are applied correctly in session refresh request sequence"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovsso(flow)
        String idToken = createSession.jsonPath().get("id_token")

        Response initRefreshSession = Steps.startSessionRefreshInSsoOidcWithOrigin(flow, idToken, flow.oidcClientA.fullBaseUrl)
        Response initLoginResponse = Steps.followRedirectWithOrigin(flow, initRefreshSession, flow.oidcClientA.fullBaseUrl)
        Response oauthLoginResponse = Steps.followRedirectWithOrigin(flow, initLoginResponse, flow.oidcClientA.fullBaseUrl)
        Response initConsentResponse = Steps.followRedirectWithOrigin(flow, oauthLoginResponse, flow.oidcClientA.fullBaseUrl)
        Response oauthConsentResponse = Steps.followRedirectWithOrigin(flow, initConsentResponse, flow.oidcClientA.fullBaseUrl)

        assertEquals("true", initRefreshSession.getHeader("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is present and has correct value")
        assertEquals((flow.oidcClientA.fullBaseUrl).toString(), initRefreshSession.getHeader("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is present and has correct value")

        assertEquals("true", initLoginResponse.getHeader("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is present and has correct value")
        assertEquals((flow.oidcClientA.fullBaseUrl).toString(), initLoginResponse.getHeader("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is present and has correct value")

        assertEquals("true", oauthLoginResponse.getHeader("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is present and has correct value")
        assertEquals((flow.oidcClientA.fullBaseUrl).toString(), oauthLoginResponse.getHeader("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is present and has correct value")

        assertEquals("true", initConsentResponse.getHeader("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is present and has correct value")
        assertEquals((flow.oidcClientA.fullBaseUrl).toString(), initConsentResponse.getHeader("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is present and has correct value")

        assertEquals("true", oauthConsentResponse.getHeader("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is present and has correct value")
        assertEquals((flow.oidcClientA.fullBaseUrl).toString(), oauthConsentResponse.getHeader("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is present and has correct value")
    }

    @Feature("AUTHENTICATION")
    def "Cross-Origin Resource Sharing headers are not applied in login request sequence"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithParamsAndOrigin(flow, paramsMap, flow.oidcClientA.fullBaseUrl)
        Response initLoginResponse = Steps.startSessionInSessionServiceWithOrigin(flow, oidcServiceInitResponse, flow.oidcClientA.fullBaseUrl)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLoginResponse)
        Response callbackResponse = Steps.followRedirectWithCookiesAndOrigin(flow, taraAuthentication, flow.sessionService.cookies, flow.oidcClientA.fullBaseUrl)
        Response loginVerifierResponse = Steps.followRedirectWithOrigin(flow, callbackResponse, flow.oidcClientA.fullBaseUrl)
        Response initConsentResponse = Steps.followRedirectWithOrigin(flow, loginVerifierResponse, flow.oidcClientA.fullBaseUrl)
        Response consentVerifierResponse = Steps.followRedirectWithOrigin(flow, initConsentResponse, flow.oidcClientA.fullBaseUrl)


        assertTrue(!oidcServiceInitResponse.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in login request sequence")
        assertTrue(!oidcServiceInitResponse.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in login request sequence")

        assertTrue(!callbackResponse.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in login request sequence")
        assertTrue(!callbackResponse.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in login request sequence")

        assertTrue(!loginVerifierResponse.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in login request sequence")
        assertTrue(!loginVerifierResponse.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in login request sequence")

        assertTrue(!consentVerifierResponse.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in login request sequence")
        assertTrue(!consentVerifierResponse.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in login request sequence")
    }

    @Feature("AUTHENTICATION")
    def "Cross-Origin Resource Sharing headers are not applied in session continuation request sequence"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithOrigin(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl, flow.oidcClientB.fullBaseUrl)
        Steps.followRedirectWithOrigin(flow, oidcServiceInitResponse, flow.oidcClientB.fullBaseUrl)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", flow.getLoginChallenge().toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))
        Response continueWithExistingSession = Requests.postRequestWithCookiesParamsAndOrigin(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies, formParams, flow.oidcClientB.fullBaseUrl)

        Response loginVerifierResponse = Steps.followRedirectWithOrigin(flow, continueWithExistingSession, flow.oidcClientB.fullBaseUrl)
        Response initConsentResponse = Steps.followRedirectWithOrigin(flow, loginVerifierResponse, flow.oidcClientB.fullBaseUrl)
        Response consentVerifierResponse = Steps.followRedirectWithOrigin(flow, initConsentResponse, flow.oidcClientB.fullBaseUrl)


        assertTrue(!oidcServiceInitResponse.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in session continuation request sequence")
        assertTrue(!oidcServiceInitResponse.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in session continuation request sequence")

        assertTrue(!continueWithExistingSession.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in session continuation request sequence")
        assertTrue(!continueWithExistingSession.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in session continuation request sequence")

        assertTrue(!loginVerifierResponse.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in session continuation request sequence")
        assertTrue(!loginVerifierResponse.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in session continuation request sequence")

        assertTrue(!consentVerifierResponse.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in session continuation request sequence")
        assertTrue(!consentVerifierResponse.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in session continuation request sequence")
    }

    @Feature("AUTHENTICATION")
    def "Cross-Origin Resource Sharing headers are not applied in logout with session continuation request sequence"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)

        Response continueWithExistingSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueWithExistingSession.jsonPath().get("id_token")

        Response oauthLogout = Steps.startLogoutWithOrigin(flow, idToken, flow.oidcClientB.fullBaseUrl, flow.oidcClientB.fullBaseUrl)
        Response initLogout = Steps.followRedirectWithOrigin(flow, oauthLogout, flow.oidcClientA.fullBaseUrl)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "logoutChallenge", flow.getLogoutChallenge().toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))
        Response logoutContinueSession = Requests.postRequestWithCookiesParamsAndOrigin(flow, flow.sessionService.fullLogoutContinueSessionUrl, Collections.emptyMap(),  formParams, flow.oidcClientB.fullBaseUrl)

        assertTrue(!oauthLogout.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in logout with session continuation request sequence")
        assertTrue(!oauthLogout.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in logout with session continuation request sequence")

        assertTrue(!initLogout.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in logout with session continuation request sequence")
        assertTrue(!initLogout.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in logout with session continuation request sequence")

        assertTrue(!logoutContinueSession.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in logout with session continuation request sequence")
        assertTrue(!logoutContinueSession.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in logout with session continuation request sequence")
    }

    @Feature("AUTHENTICATION")
    def "Cross-Origin Resource Sharing headers are not applied in logout with end session request sequence"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)

        Response continueWithExistingSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueWithExistingSession.jsonPath().get("id_token")

        Response oauthLogout = Steps.startLogoutWithOrigin(flow, idToken, flow.oidcClientB.fullBaseUrl, flow.oidcClientB.fullBaseUrl)
        Steps.followRedirectWithOrigin(flow, oauthLogout, flow.oidcClientA.fullBaseUrl)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "logoutChallenge", flow.getLogoutChallenge().toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))
        Response logoutEndSession = Requests.postRequestWithCookiesParamsAndOrigin(flow, flow.sessionService.fullLogoutEndSessionUrl, Collections.emptyMap(),  formParams, flow.oidcClientB.fullBaseUrl)

        assertTrue(!logoutEndSession.getHeaders().hasHeaderWithName("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials header is not present in logout with end session request sequence")
        assertTrue(!logoutEndSession.getHeaders().hasHeaderWithName("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin header is not present in logout with end session request sequence")
    }
}
