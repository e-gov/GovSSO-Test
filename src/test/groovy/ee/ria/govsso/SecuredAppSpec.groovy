package ee.ria.govsso

import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.response.Response
import org.apache.http.HttpStatus

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.allOf
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.lessThan
import static org.hamcrest.Matchers.not
import static org.hamcrest.Matchers.notNullValue

@Feature("SECURED_APP")
class SecuredAppSpec extends GovSsoOidcSpecification {

    def "Given authentication in secured app client, then update session succeeds"() {
        given:
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)

        when:
        Response updateSession = Steps.updateSession(flow, ClientStore.mockSecuredApp)

        then:
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, updateSession.body.path("id_token")).JWTClaimsSet
        assertThat("Correct audience value", claims.audience[0], is(ClientStore.mockSecuredApp.clientId))
        assertThat("Correct subject value", claims.subject, is("EE38001085718"))
        assertThat("Correct given name value", claims.getClaim("given_name"), is("JAAK-KRISTJAN"))
    }

    @Feature("CONSENT_INIT_ENDPOINT")
    def "Given authentication in secured app client, then the oidc session cookie is cleared on consent"() {
        given: "Authenticate in TARA with the secured app client"
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, ClientStore.mockSecuredApp)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)

        when: "Follow the flow up to the consent init response"
        Response taraCallback = Steps.followRedirect(flow, taraAuthentication)
        // Hydra issues the session cookie on the login verifier response, GovSSO clears it on the next hop.
        Response loginVerifier = Steps.followRedirect(flow, taraCallback)
        Response initConsent = Steps.followRedirect(flow, loginVerifier)

        then: "The session cookie issued to the secured app session is cleared by being re-sent already expired"
        assertThat("Oidc session cookie is returned", initConsent.detailedCookie("__Host-ory_hydra_session"), notNullValue())
        assertThat("Oidc session cookie is expired",
                initConsent.detailedCookie("__Host-ory_hydra_session").expiryDate, lessThan(new Date()))
    }

    def "Given authentication in secured app client, then authentication in default client creates a new session"() {
        given:
        Response appSession = Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        JWTClaimsSet appClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, appSession.path("id_token")).JWTClaimsSet
        String appRefreshToken = flow.refreshToken

        when: "Start an authentication with a default client in the same browser"
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, ClientStore.clientA)
        Response initLogin = Steps.followRedirect(flow, oidcAuth)

        then: "The secured app session is not offered for continuation, reauthentication in TARA is required"
        assertThat("Correct HTTP status code", initLogin.statusCode, is(HttpStatus.SC_MOVED_TEMPORARILY))
        assertThat("Redirected to TARA", initLogin.header("location"), containsString(flow.taraService.host))

        when: "Complete the authentication"
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response webSession = Steps.followRedirectsToClientApplication(flow, taraAuthentication, ClientStore.clientA)

        then: "A new session is created instead of continuing the secured app session"
        JWTClaimsSet webClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, webSession.path("id_token")).JWTClaimsSet
        assertThat("Same subject value", webClaims.subject, is(appClaims.subject))
        assertThat("New session ID", webClaims.getClaim("sid"), not(is(appClaims.getClaim("sid"))))

        and: "The secured app session is not terminated"
        assertThat("App session can still be updated",
                Steps.tryUpdateSession(flow, ClientStore.mockSecuredApp, [refresh_token: appRefreshToken]).statusCode, is(HttpStatus.SC_OK))
    }

    def "Given authentication in secured app client, then authentication in secured app client creates a new independent session"() {
        given:
        Response firstSession = Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        JWTClaimsSet firstClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, firstSession.path("id_token")).JWTClaimsSet
        String firstRefreshToken = flow.refreshToken

        when: "Authenticate with the secured app client again in the same browser"
        Response secondSession = Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)

        then: "A new session is created"
        JWTClaimsSet secondClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, secondSession.path("id_token")).JWTClaimsSet
        assertThat("Same subject value", secondClaims.subject, is(firstClaims.subject))
        assertThat("New session ID", secondClaims.getClaim("sid"), not(is(firstClaims.getClaim("sid"))))

        and: "The first app session is not terminated by the second authentication"
        assertThat("First session can still be updated",
                Steps.tryUpdateSession(flow, ClientStore.mockSecuredApp, [refresh_token: firstRefreshToken]).statusCode, is(HttpStatus.SC_OK))
    }

    @Feature("LOGIN_INIT_ENDPOINT")
    def "Given authentication in default client, then authentication in secured app client creates a new session"() {
        given:
        Response webSession = Steps.authenticateWithIdCardInGovSso(flow, ClientStore.clientA)
        JWTClaimsSet webClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, webSession.path("id_token")).JWTClaimsSet

        when: "Authenticate with the secured app client in the same browser"
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, ClientStore.mockSecuredApp)
        Response initLogin = Steps.followRedirect(flow, oidcAuth)

        then: "The existing session is not offered for continuation, the authentication request is restarted instead"
        assertThat("Correct HTTP status code", initLogin.statusCode, is(HttpStatus.SC_MOVED_TEMPORARILY))
        assertThat("Redirected back to the authorization request", initLogin.header("location"),
                allOf(containsString("/oauth2/auth"),
                        containsString("client_id=" + ClientStore.mockSecuredApp.clientId)))

        when: "Follow the restarted authentication request through TARA"
        Response restartedOidcAuth = Steps.followRedirect(flow, initLogin)
        Response restartedInitLogin = Steps.followRedirect(flow, restartedOidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, restartedInitLogin)
        Response appSession = Steps.followRedirectsToClientApplication(flow, taraAuthentication, ClientStore.mockSecuredApp)

        then: "A new session is created"
        JWTClaimsSet appClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, appSession.path("id_token")).JWTClaimsSet
        assertThat("Same subject value", appClaims.subject, is(webClaims.subject))
        assertThat("New session ID", appClaims.getClaim("sid"), not(is(webClaims.getClaim("sid"))))
    }

    @Feature("LOGIN_INIT_ENDPOINT")
    def "Given authentication in default client, then abandoned authentication in secured app client terminates the existing session"() {
        given:
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.clientA)
        String webRefreshToken = flow.refreshToken

        when: "Secured app authentication is started, but abandoned before authenticating in TARA"
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, ClientStore.mockSecuredApp)
        Response initLogin = Steps.followRedirect(flow, oidcAuth)

        then: "The authentication request is restarted"
        assertThat("Correct HTTP status code", initLogin.statusCode, is(HttpStatus.SC_MOVED_TEMPORARILY))

        and: "The browser is no longer carrying a session"
        // The cookie is cleared by being re-sent already expired.
        assertThat("Oidc session cookie is expired",
                initLogin.detailedCookie("__Host-ory_hydra_session").expiryDate, lessThan(new Date()))

        and: "The existing web session is terminated"
        Response webUpdate = Steps.tryUpdateSession(flow, ClientStore.clientA, [refresh_token: webRefreshToken])
        assertThat("Web session can no longer be updated", webUpdate.statusCode, is(HttpStatus.SC_BAD_REQUEST))
        assertThat("Correct error", webUpdate.body.jsonPath().getString("error"), is("invalid_grant"))
    }

    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Given authentication in default client, then continuing session in secured app client fails"() {
        given: "Existing web session and a valid CSRF token from its session continuation view"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.clientA)
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, ClientStore.clientB)
        Response initLogin = Steps.followRedirect(flow, oidcAuth)
        String csrf = initLogin.htmlPath().get("**.find {it.@name == '_csrf'}.@value")

        and: "Login challenge for the secured app client. /login/init is deliberately not requested, as it would end the existing session"
        Steps.startAuthenticationInSsoOidc(flow, ClientStore.mockSecuredApp)

        when: "Continue session is requested directly, bypassing the browser flow"
        Response continueSession = Requests.postRequestWithParams(flow, flow.sessionService.fullContinueSessionUrl,
                [loginChallenge: flow.loginChallenge,
                 _csrf         : csrf])

        then:
        continueSession.then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body(
                        "error", is("USER_INPUT"),
                        "path", is("/login/continuesession"),
                        "message", is("Ebakorrektne päring."))
    }
}
