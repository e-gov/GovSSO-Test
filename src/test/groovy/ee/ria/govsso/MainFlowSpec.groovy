package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.hamcrest.Matchers.*
import static org.hamcrest.MatcherAssert.assertThat

class MainFlowSpec extends GovSsoSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Feature("BUSINESS_LOGIC")
    @Feature("LOGIN_INIT_ENDPOINT")
    def "Authentication with Mobile-ID"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)

        Response taraAuthentication = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", initLogin)

        Response consentVerifier = Steps.followRedirectsToClientApplication(flow, taraAuthentication)

        Response token = Steps.getIdentityTokenResponseWithDefaults(flow, consentVerifier)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, token.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat("Correct authentication method value", claims.getClaim("amr"), is(["mID"]))
        assertThat("Correct audience value", claims.getAudience().get(0), is(flow.oidcClientA.clientId))
        assertThat("Correct subject value", claims.getSubject(), is("EE60001017716"))
        assertThat("Correct given name value", claims.getClaim("given_name"), is("ONE"))
    }

    @Feature("BUSINESS_LOGIC")
    @Feature("LOGIN_INIT_ENDPOINT")
    def "Authenticate with Smart-ID"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)

        Response taraAuthentication = TaraSteps.authenticateWithSidInTARA(flow, "30303039914", initLogin)

        Response consentVerifier = Steps.followRedirectsToClientApplication(flow, taraAuthentication)

        Response token = Steps.getIdentityTokenResponseWithDefaults(flow, consentVerifier)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, token.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat("Correct authentication method value", claims.getClaim("amr"), is(["smartid"]))
        assertThat("Correct audience value", claims.getAudience().get(0), is(flow.oidcClientA.clientId))
        assertThat("Correct subject value", claims.getSubject(), is("EE30303039914"))
        assertThat("Correct given name value", claims.getClaim("given_name"), is("OK"))
    }

    @Feature("BUSINESS_LOGIC")
    @Feature("LOGIN_INIT_ENDPOINT")
    def "Authenticate with ID-Card"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)

        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)

        Response consentVerifier = Steps.followRedirectsToClientApplication(flow, taraAuthentication)

        Response token = Steps.getIdentityTokenResponseWithDefaults(flow, consentVerifier)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, token.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat("Correct authentication method value", claims.getClaim("amr"), is(["idcard"]))
        assertThat("Correct audience value", claims.getAudience().get(0), is(flow.oidcClientA.clientId))
        assertThat("Correct subject value", claims.getSubject(), is("EE38001085718"))
        assertThat("Correct given name value", claims.getClaim("given_name"), is("JAAK-KRISTJAN"))
    }

    @Feature("BUSINESS_LOGIC")
    @Feature("LOGIN_INIT_ENDPOINT")
    def "Authenticate with eIDAS"() {
        expect:
        Response createSession = Steps.authenticateWithEidasInGovSso(flow, "high", "E")

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, createSession.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat("Correct authentication method value", claims.getClaim("amr"), is(["eidas"]))
        assertThat("Correct audience value", claims.getAudience().get(0), is(flow.oidcClientA.clientId))
        assertThat("Correct subject value", claims.getSubject(), is("CA12345"))
        assertThat("Correct given name value", claims.getClaim("given_name"), is("javier"))
    }

    @Feature("BUSINESS_LOGIC")
    @Feature("LOGIN_INIT_ENDPOINT")
    def "Authentication with ID-card in client-A and update session"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response updateSession = Steps.getSessionUpdateResponse(flow)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, updateSession.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat("Correct authentication method value", claims.getClaim("amr"), is(["idcard"]))
        assertThat("Correct audience value", claims.getAudience().get(0), is(flow.oidcClientA.clientId))
        assertThat("Correct subject value", claims.getSubject(), is("EE38001085718"))
        assertThat("Correct given name value", claims.getClaim("given_name"), is("JAAK-KRISTJAN"))
    }

    @Feature("BUSINESS_LOGIC")
    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Authentication with ID-card in client-A and continue session in client-B"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        JWTClaimsSet claimsClientA = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, createSession.getBody().jsonPath().get("id_token")).getJWTClaimsSet()

        Response continueSession = Steps.continueWithExistingSession(flow)

        JWTClaimsSet claimsClientB = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, continueSession.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat("Correct authentication method value", claimsClientB.getClaim("amr"), is(["idcard"]))
        assertThat("Correct audience value", claimsClientB.getAudience().get(0), is(flow.oidcClientB.clientId))
        assertThat("Correct subject value", claimsClientB.getSubject(), is("EE38001085718"))
        assertThat("Correct session ID", claimsClientB.getClaim("sid"), is(claimsClientA.getClaim("sid")))
    }

    @Feature("BUSINESS_LOGIC")
    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Authentication with ID-card in client-A and continue session in client-A"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        JWTClaimsSet claimsClientA1 = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, createSession.getBody().jsonPath().get("id_token")).getJWTClaimsSet()

        Response continueSession = Steps.continueWithExistingSession(flow, flow.oidcClientA.clientId, flow.oidcClientA.clientSecret, flow.oidcClientA.fullResponseUrl)

        JWTClaimsSet claimsClientA2 = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, continueSession.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat("Correct authentication method value", claimsClientA2.getClaim("amr"), is(["idcard"]))
        assertThat("Correct audience value", claimsClientA2.getAudience().get(0), is(flow.oidcClientA.clientId))
        assertThat("Correct subject value", claimsClientA2.getSubject(), is("EE38001085718"))
        assertThat("Correct session ID", claimsClientA1.getClaim("sid"), is(claimsClientA2.getClaim("sid")))
    }

    @Feature("BUSINESS_LOGIC")
    @Feature("LOGIN_REAUTHENTICATE_ENDPOINT")
    def "Authentication with ID-card in client-A and reauthenticate in client-B"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        JWTClaimsSet claimsClientA = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, createSession.getBody().jsonPath().get("id_token")).getJWTClaimsSet()

        Response reauthenticate = Steps.reauthenticate(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)

        JWTClaimsSet claimsClientB = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, reauthenticate.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat("Correct authentication method value", claimsClientB.getClaim("amr"), is(["idcard"]))
        assertThat("Correct audience value", claimsClientB.getAudience().get(0), is(flow.oidcClientB.clientId))
        assertThat("Correct subject value", claimsClientB.getSubject(), is("EE38001085718"))
        assertThat("Correct given name", claimsClientB.getClaim("given_name"), is("JAAK-KRISTJAN"))
        assertThat("New session ID", claimsClientB.getClaim("sid"), not(is(claimsClientA.getClaim("sid"))))
    }

    @Feature("BUSINESS_LOGIC")
    @Feature("LOGIN_REAUTHENTICATE_ENDPOINT")
    def "Reauthenticate in client-B with high acr after acr discrepancy with client-A session"() {
        expect:
        Steps.authenticateWithEidasInGovSso(flow, "substantial", "C")

        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcAuth)

        Response reauthenticate = Steps.reauthenticateAfterAcrDiscrepancy(flow)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, reauthenticate.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat("Correct acr value in token", claims.getClaim("acr"), is("high"))
        assertThat("Correct audience value", claims.getAudience().get(0), is(flow.oidcClientB.clientId))
    }

    @Feature("BUSINESS_LOGIC")
    @Feature("LOGOUT_INIT_ENDPOINT")
    def "Log out from single client session"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        String idToken = createSession.jsonPath().get("id_token")

        Response logout = Steps.logoutSingleClientSession(flow, idToken, flow.oidcClientA.fullLogoutRedirectUrl)
        assertThat("Correct status code", logout.getStatusCode(), is(302))
        assertThat("Correct redirect URL", logout.getHeader("Location"), startsWith((flow.oidcClientA.fullLogoutRedirectUrl).toString()))
    }

    @Feature("BUSINESS_LOGIC")
    @Feature("LOGOUT_INIT_ENDPOINT")
    def "Log out after session update"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response updateSession = Steps.getSessionUpdateResponse(flow)
        String idToken2 = updateSession.getBody().jsonPath().get("id_token")

        Response logout = Steps.logoutSingleClientSession(flow, idToken2, flow.oidcClientA.fullLogoutRedirectUrl)
        assertThat("Correct status code", logout.getStatusCode(), is(302))
        assertThat("Correct redirect URL", logout.getHeader("Location"), startsWith((flow.oidcClientA.fullLogoutRedirectUrl).toString()))
    }

    @Feature("BUSINESS_LOGIC")
    @Feature("LOGOUT_END_SESSION_ENDPOINT")
    def "Log out with end session"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.jsonPath().get("id_token")

        Response initLogout = Steps.logout(flow, idToken, flow.oidcClientB.fullLogoutRedirectUrl, flow.sessionService.fullLogoutEndSessionUrl)
        Response logoutVerifier = Steps.followRedirect(flow, initLogout)
        assertThat("Correct status code", logoutVerifier.getStatusCode(), is(302))
        assertThat("Correct redirect URL", logoutVerifier.getHeader("Location"), startsWith((flow.oidcClientB.fullLogoutRedirectUrl).toString()))
    }

    @Feature("BUSINESS_LOGIC")
    @Feature("LOGOUT_CONTINUE_SESSION_ENDPOINT")
    def "Log out with continue session"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.jsonPath().get("id_token")

        Response initLogout = Steps.logout(flow, idToken, flow.oidcClientB.fullLogoutRedirectUrl, flow.sessionService.fullLogoutContinueSessionUrl)
        assertThat("Correct status code", initLogout.getStatusCode(), is(302))
        assertThat("Correct redirect URL", initLogout.getHeader("Location"), startsWith((flow.oidcClientB.fullLogoutRedirectUrl).toString()))
    }
}