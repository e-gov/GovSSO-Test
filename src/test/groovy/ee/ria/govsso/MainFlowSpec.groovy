package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.junit.jupiter.api.Assertions.assertEquals
import static org.junit.jupiter.api.Assertions.assertNotEquals
import static org.junit.jupiter.api.Assertions.assertTrue

class MainFlowSpec extends GovSsoSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Feature("AUTHENTICATION")
    def "Authentication with Mobile-ID"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)

        Response authenticationFinishedResponse = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", sessionServiceRedirectToTaraResponse)

        Response oidcServiceConsentResponse = Steps.followRedirectsToClientApplication(flow, authenticationFinishedResponse)

        Response tokenResponse = Steps.getIdentityTokenResponseWithDefaults(flow, oidcServiceConsentResponse)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertEquals(flow.oidcClientA.clientId, claims.getAudience().get(0), "Correct aud value")
        assertEquals("EE60001017716", claims.getSubject(), "Correct subject value")
        assertEquals("ONE", claims.getClaim("given_name"), "Correct given name")
    }

    @Feature("AUTHENTICATION")
    def "Authenticate with Smart-ID"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)

        Response authenticationFinishedResponse = TaraSteps.authenticateWithSidInTARA(flow, "30303039914", sessionServiceRedirectToTaraResponse)

        Response oidcServiceConsentResponse = Steps.followRedirectsToClientApplication(flow, authenticationFinishedResponse)

        Response tokenResponse = Steps.getIdentityTokenResponseWithDefaults(flow, oidcServiceConsentResponse)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertEquals(flow.oidcClientA.clientId, claims.getAudience().get(0), "Correct aud value")
        assertEquals("EE30303039914", claims.getSubject(), "Correct subject value")
        assertEquals("QUALIFIED OK1", claims.getClaim("given_name"), "Correct given name")
    }

    @Feature("AUTHENTICATION")
    def "Authenticate with ID-Card"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)

        Response authenticationFinishedResponse = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)

        Response oidcServiceConsentResponse = Steps.followRedirectsToClientApplication(flow, authenticationFinishedResponse)

        Response tokenResponse = Steps.getIdentityTokenResponseWithDefaults(flow, oidcServiceConsentResponse)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertEquals(flow.oidcClientA.clientId, claims.getAudience().get(0), "Correct aud value")
        assertEquals("EE38001085718", claims.getSubject(), "Correct subject value")
        assertEquals("JAAK-KRISTJAN", claims.getClaim("given_name"), "Correct given name")
    }

    @Feature("AUTHENTICATION")
    def "Authenticate with eIDAS"() {
        expect:
        Response createSessionWithEidas = Steps.authenticateWithEidasInGovsso(flow, "high", "E")

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, createSessionWithEidas.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertEquals(flow.oidcClientA.clientId, claims.getAudience().get(0), "Correct aud value")
        assertEquals("CA12345", claims.getSubject(), "Correct subject value")
        assertEquals("javier", claims.getClaim("given_name"), "Correct given name")
    }

    @Feature("AUTHENTICATION")
    def "Authentication with ID-card in client-A and refresh session"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovsso(flow)
        String idToken = createSession.jsonPath().get("id_token")
        Response refreshSession = Steps.refreshSessionWithDefaults(flow, idToken)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, refreshSession.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertEquals(flow.oidcClientA.clientId, claims.getAudience().get(0), "Correct aud value")
        assertEquals("EE38001085718", claims.getSubject(), "Correct subject value")
        assertEquals("JAAK-KRISTJAN", claims.getClaim("given_name"), "Correct given name")
    }

    @Feature("AUTHENTICATION")
    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Authentication with ID-card in client-A and continue session in client-B"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovsso(flow)
        JWTClaimsSet claimsClientA = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, createSession.getBody().jsonPath().get("id_token")).getJWTClaimsSet()

        Response continueWithExistingSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)

        JWTClaimsSet claimsClientB = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, continueWithExistingSession.getBody().jsonPath().get("id_token"), flow.oidcClientB.clientId).getJWTClaimsSet()
        assertEquals(flow.oidcClientB.clientId, claimsClientB.getAudience().get(0), "Correct aud value")
        assertEquals("EE38001085718", claimsClientB.getSubject(), "Correct subject value")
        assertEquals(claimsClientA.getClaim("sid"), claimsClientB.getClaim("sid"), "Correct session ID")
    }

    @Feature("AUTHENTICATION")
    @Feature("LOGIN_REAUTHENTICATE_ENDPOINT")
    def "Authentication with ID-card in client-A and reauthenticate in client-B"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovsso(flow)
        JWTClaimsSet claimsClientA = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, createSession.getBody().jsonPath().get("id_token")).getJWTClaimsSet()

        Response reauthenticate = Steps.reauthenticate(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)

        JWTClaimsSet claimsClientB = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, reauthenticate.getBody().jsonPath().get("id_token"), flow.oidcClientB.clientId).getJWTClaimsSet()
        assertEquals(flow.oidcClientB.clientId, claimsClientB.getAudience().get(0), "Correct aud value")
        assertEquals("EE38001085718", claimsClientB.getSubject(), "Correct subject value")
        assertEquals("JAAK-KRISTJAN", claimsClientB.getClaim("given_name"), "Correct given name")
        assertNotEquals(claimsClientA.getClaim("sid"), claimsClientB.getClaim("sid"), "New session ID")
    }

    @Feature("LOGOUT")
    def "Logout from single client session"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovsso(flow)
        String idToken = createSession.jsonPath().get("id_token")
        Response logout = Steps.logoutSingleClientSession(flow, idToken, flow.oidcClientA.fullBaseUrl)

        assertEquals(302, logout.getStatusCode(), "Correct status code")
        assertTrue(logout.getHeader("Location")==(flow.oidcClientA.fullBaseUrl), "Correct redirect URL")
    }

    @Feature("LOGOUT")
    def "Logout after session refresh"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovsso(flow)
        String idToken = createSession.jsonPath().get("id_token")

        Response refreshSession = Steps.refreshSessionWithDefaults(flow, idToken)
        String idToken2 = refreshSession.getBody().jsonPath().get("id_token")

        Response logoutResponse = Steps.logoutSingleClientSession(flow, idToken2, flow.oidcClientA.fullBaseUrl)

        assertEquals(302, logoutResponse.getStatusCode(), "Correct status code")
        assertTrue(logoutResponse.getHeader("Location")==(flow.oidcClientA.fullBaseUrl), "Correct redirect URL")
    }

    @Feature("LOGOUT")
    def "Logout with end session"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)

        Response continueWithExistingSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueWithExistingSession.jsonPath().get("id_token")

        Response logoutResponse = Steps.logout(flow, idToken, flow.oidcClientB.fullBaseUrl, flow.sessionService.fullLogoutEndSessionUrl)
        Response oidcLogout = Steps.followRedirect(flow, logoutResponse)

        assertEquals(302, oidcLogout.getStatusCode(), "Correct status code")
        assertTrue(oidcLogout.getHeader("Location")==(flow.oidcClientB.fullBaseUrl), "Correct redirect URL")
    }

    //TODO: review location encoding in logoutResponse
    @Feature("LOGOUT")
    def "Logout with continue session"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)

        Response continueWithExistingSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueWithExistingSession.jsonPath().get("id_token")

        Response logoutResponse = Steps.logout(flow, idToken, flow.oidcClientB.fullBaseUrl, flow.sessionService.fullLogoutContinueSessionUrl)

        assertEquals(302, logoutResponse.getStatusCode(), "Correct status code")
        assertTrue(logoutResponse.getHeader("Location").contains(flow.oidcClientB.host), "Correct redirect URL")
    }
}