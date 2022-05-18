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
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)

        Response taraAuthentication = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", initLogin)

        Response consentVerifier = Steps.followRedirectsToClientApplication(flow, taraAuthentication)

        Response token = Steps.getIdentityTokenResponseWithDefaults(flow, consentVerifier)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, token.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertEquals(flow.oidcClientA.clientId, claims.getAudience().get(0), "Correct aud value")
        assertEquals("EE60001017716", claims.getSubject(), "Correct subject value")
        assertEquals("ONE", claims.getClaim("given_name"), "Correct given name")
    }

    @Feature("AUTHENTICATION")
    def "Authenticate with Smart-ID"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)

        Response taraAuthentication = TaraSteps.authenticateWithSidInTARA(flow, "30303039914", initLogin)

        Response consentVerifier = Steps.followRedirectsToClientApplication(flow, taraAuthentication)

        Response token = Steps.getIdentityTokenResponseWithDefaults(flow, consentVerifier)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, token.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertEquals(flow.oidcClientA.clientId, claims.getAudience().get(0), "Correct aud value")
        assertEquals("EE30303039914", claims.getSubject(), "Correct subject value")
        assertEquals("QUALIFIED OK1", claims.getClaim("given_name"), "Correct given name")
    }

    @Feature("AUTHENTICATION")
    def "Authenticate with ID-Card"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)

        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)

        Response consentVerifier = Steps.followRedirectsToClientApplication(flow, taraAuthentication)

        Response token = Steps.getIdentityTokenResponseWithDefaults(flow, consentVerifier)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, token.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertEquals(flow.oidcClientA.clientId, claims.getAudience().get(0), "Correct aud value")
        assertEquals("EE38001085718", claims.getSubject(), "Correct subject value")
        assertEquals("JAAK-KRISTJAN", claims.getClaim("given_name"), "Correct given name")
    }

    @Feature("AUTHENTICATION")
    def "Authenticate with eIDAS"() {
        expect:
        Response createSession = Steps.authenticateWithEidasInGovsso(flow, "high", "E")

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, createSession.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
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

        Response continueSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)

        JWTClaimsSet claimsClientB = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, continueSession.getBody().jsonPath().get("id_token"), flow.oidcClientB.clientId).getJWTClaimsSet()
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

    @Feature("LOGIN_INIT_ENDPOINT")
    @Feature("AUTHENTICATION")
    def "Reauthenticate in client-B with high acr after acr discrepancy with client-A session"() {
        expect:
        Steps.authenticateWithEidasInGovsso(flow, "substantial", "C")

        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcAuth)

        Response reauthenticate = Steps.reauthenticateAfterAcrDiscrepancy(flow)
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, reauthenticate.getBody().jsonPath().get("id_token"), flow.oidcClientB.clientId).getJWTClaimsSet()

        assertEquals("high", claims.getClaim("acr"), "Correct acr value in token")
        assertEquals(flow.oidcClientB.clientId, claims.getAudience().get(0), "Correct aud value")
    }

    @Feature("LOGOUT")
    def "Log out from single client session"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovsso(flow)
        String idToken = createSession.jsonPath().get("id_token")
        Response logout = Steps.logoutSingleClientSession(flow, idToken, flow.oidcClientA.fullBaseUrl)

        assertEquals(302, logout.getStatusCode(), "Correct status code")
        assertTrue(logout.getHeader("Location")==(flow.oidcClientA.fullBaseUrl), "Correct redirect URL")
    }

    @Feature("LOGOUT")
    def "Log out after session refresh"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovsso(flow)
        String idToken = createSession.jsonPath().get("id_token")

        Response refreshSession = Steps.refreshSessionWithDefaults(flow, idToken)
        String idToken2 = refreshSession.getBody().jsonPath().get("id_token")

        Response logout = Steps.logoutSingleClientSession(flow, idToken2, flow.oidcClientA.fullBaseUrl)

        assertEquals(302, logout.getStatusCode(), "Correct status code")
        assertTrue(logout.getHeader("Location")==(flow.oidcClientA.fullBaseUrl), "Correct redirect URL")
    }

    @Feature("LOGOUT")
    def "Log out with end session"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueSession.jsonPath().get("id_token")

        Response initLogout = Steps.logout(flow, idToken, flow.oidcClientB.fullBaseUrl, flow.sessionService.fullLogoutEndSessionUrl)
        Response logoutVerifier = Steps.followRedirect(flow, initLogout)

        assertEquals(302, logoutVerifier.getStatusCode(), "Correct status code")
        assertTrue(logoutVerifier.getHeader("Location")==(flow.oidcClientB.fullBaseUrl), "Correct redirect URL")
    }

    @Feature("LOGOUT")
    def "Log out with continue session"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueSession.jsonPath().get("id_token")

        Response initLogout = Steps.logout(flow, idToken, flow.oidcClientB.fullBaseUrl, flow.sessionService.fullLogoutContinueSessionUrl)

        assertEquals(302, initLogout.getStatusCode(), "Correct status code")
        assertTrue(initLogout.getHeader("Location").contains(flow.oidcClientB.host), "Correct redirect URL")
    }
}