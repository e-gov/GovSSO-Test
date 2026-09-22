package ee.ria.govsso

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import ee.ria.govsso.database.SqlQueries
import ee.ria.govsso.model.ClientType
import io.qameta.allure.Feature
import io.restassured.response.Response
import org.apache.http.HttpStatus
import spock.lang.Ignore
import spock.lang.Issue
import spock.lang.PendingFeature
import spock.lang.Tag

import java.time.Instant

import static ee.ria.govsso.Steps.AUTH_HANDOVER_SCOPE
import static ee.ria.govsso.Steps.AUTH_HANDOVER_TOKEN_PARAM
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

@Tag("auth-handover")
@Feature("AUTH_HANDOVER")
class AuthHandoverSpec extends GovSsoOidcSpecification {

    // The app and the browser are separate agents with separate GovSSO sessions.
    Flow webFlow = new Flow()

    def setup() {
        wireFlow(webFlow)
    }

    def "Session update with auth handover scope returns a handover token response"() {
        given: "Create (app) session with SECURED_APP client"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)

        when: "Request auth handover token"
        Response tokenResponse = Steps.getHandoverTokenResponse(flow, ClientStore.mockSecuredApp)

        then: "Response contains the required fields"
        assertThat("Response contains access token", tokenResponse.path("access_token"), notNullValue())
        assertThat("Correct token type", tokenResponse.jsonPath().getString("token_type"), equalToIgnoringCase("bearer"))
        assertThat("Response contains ID token", tokenResponse.path("id_token"), notNullValue())
        assertThat("Response contains refresh token", tokenResponse.path("refresh_token"), notNullValue())

        and: "The handover token is returned as access_token"
        JWTClaimsSet handoverTokenClaims = SignedJWT.parse(tokenResponse.path("access_token")).JWTClaimsSet
        assertThat("Correct audience value", handoverTokenClaims.audience, is([flow.openIdServiceConfiguration.get("issuer")]))
        assertThat("Audience equals issuer", handoverTokenClaims.audience, is([handoverTokenClaims.issuer]))
        assertThat("Correct scope claim", handoverTokenClaims.getClaim("scope"), is(AUTH_HANDOVER_SCOPE))
    }

    def "Auth handover token carries the required claims"() {
        given: "Create (app) session with SECURED_APP client"
        Response appSession = Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        JWTClaimsSet appClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, appSession.path("id_token")).JWTClaimsSet

        when: "Request auth handover token"
        JWTClaimsSet handoverTokenClaims = SignedJWT.parse(Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)).JWTClaimsSet

        Set expectedClaims = [
                "acr", "amr", "aud", "auth_time", "birthdate",
                "client_id", "exp", "family_name", "given_name", "iat",
                "initiator", "iss", "jti", "scope", "sub"
        ]

        then: "Required claims are present and match"
        assertThat("JWT has only expected claims", handoverTokenClaims.claims.keySet(), equalTo(expectedClaims))
        assertThat("Correct JWT ID claim exists", handoverTokenClaims.JWTID, matchesPattern("([a-f0-9]{8}(-[a-f0-9]{4}){4}[a-f0-9]{8})"))
        assertThat("Correct issuer", handoverTokenClaims.issuer, equalTo(flow.openIdServiceConfiguration.get("issuer")))
        assertThat("Correct audience", handoverTokenClaims.audience, equalTo([flow.openIdServiceConfiguration.get("issuer")]))
        assertThat("Correct scope", handoverTokenClaims.getClaim("scope"), equalTo(AUTH_HANDOVER_SCOPE))
        assertThat("Correct client_id", handoverTokenClaims.getClaim("client_id"), equalTo(ClientStore.mockSecuredApp.clientId))
        assertThat("Correct initiator", handoverTokenClaims.getClaim("initiator"), equalTo(ClientType.SECURED_APP.toString()))
        assertThat("Correct subject claim", handoverTokenClaims.subject, equalTo("EE38001085718"))
        assertThat("Correct date of birth", handoverTokenClaims.getClaim("birthdate"), equalTo("1980-01-08"))
        assertThat("Correct given name", handoverTokenClaims.getClaim("given_name"), equalTo("JAAK-KRISTJAN"))
        assertThat("Correct family name", handoverTokenClaims.getClaim("family_name"), equalTo("JÕEORG"))
        assertThat("Correct LoA level", handoverTokenClaims.getClaim("acr"), equalTo("high"))
        assertThat("Correct authentication method", handoverTokenClaims.getClaim("amr"), equalTo(["idcard"]))

        assertThat("Correct authentication time", handoverTokenClaims.getClaim("auth_time"),
                equalTo(appClaims.getClaim("auth_time")))
    }

    @PendingFeature(reason = "auth handover token lifetime limit (60s) not implemented")
    def "Auth handover token has a 60 second lifetime"() {
        given: "Create (app) session with SECURED_APP client"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)

        when: "Request auth handover token"
        Response tokenResponse = Steps.getHandoverTokenResponse(flow, ClientStore.mockSecuredApp)
        JWTClaimsSet claims = SignedJWT.parse(tokenResponse.path("access_token") as String).JWTClaimsSet

        then:
        assertThat("Correct expires_in", tokenResponse.jsonPath().getInt("expires_in"), is(60))
        assertThat("Correct lifetime", claims.expirationTime.time - claims.issueTime.time, is(60_000L))
    }

    @PendingFeature(reason = "auth handover token request - missing or faulty validations")
    @Issue("AUT-3087")
    def "Auth handover token request fails when #reason"() {
        given: "Create (app) session with SECURED_APP client"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)

        // extraParams overrides the correct audience and scope that tryGetHandoverToken supplies.
        when: "Request auth handover token"
        Response tokenResponse = Steps.tryGetHandoverToken(flow, ClientStore.mockSecuredApp, extraParams)

        then:
        assertThat("Correct HTTP status code", tokenResponse.statusCode, is(HttpStatus.SC_BAD_REQUEST))
//        assertThat("Correct error", tokenResponse.jsonPath().getString("error"), is(expectedError))

        where:
        reason                              | extraParams                                        //|| expectedError
        "refresh token is invalid"          | [refresh_token: Utils.generateOryToken("ory_rt_")] //|| "invalid_grant"
        "scope='openid'"                    | [scope: "openid"]
        "scope is empty"                    | [scope: ""]
        "scope is omitted"                  | [scope: null]
        "audience is not GovSSO's base URL" | [audience: "https://not.govsso/"]                  //|| "invalid_request"
        "audience contains extra URL(s)"    | [audience: ClientStore.mockSecuredApp.accessTokenAudienceUris.join(" ")]
        // TODO: Allure logging can't handle lists in formParams, causing the request to fail - needs a solution
//        "audience contains extra URL(s)"    | [audience: ClientStore.mockSecuredApp.accessTokenAudienceUris]
        "audience is empty"                 | [audience: ""]
        "audience is omitted"               | [audience: null]
    }

    @PendingFeature(reason = "auth handover token request - missing or faulty validations")
    def "Auth handover token request fails for a client without the handover capability configured"() {
        given: "Create session with DEFAULT client"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.clientA)

        when:
        Response tokenResponse = Steps.tryGetHandoverToken(flow, ClientStore.clientA)

        then:
        assertThat("Correct HTTP status code", tokenResponse.statusCode, is(HttpStatus.SC_BAD_REQUEST))
        assertThat("Correct error", tokenResponse.jsonPath().getString("error"), is("TODO"))
    }

    def "Auth handover scope cannot be requested in the authentication request"() {
        when: "Authentication request carries the handover scope, with a client that has it configured"
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithScope(flow, ClientStore.mockSecuredApp, "openid " + AUTH_HANDOVER_SCOPE)
        Response initLogin = Steps.followRedirect(flow, oidcAuth)

        then: "Request is rejected"
        initLogin.then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body(
                        "error", is("USER_INPUT"),
                        "path", is("/login/init"),
                        "message", is("Ebakorrektne päring."))
    }

    def "Authentication with auth handover token creates a new session without TARA authentication"() {
        given: "Create app session and request handover token"
        Response appSession = Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        JWTClaimsSet appClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, appSession.path("id_token")).JWTClaimsSet
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)

        when: "Authenticate in a web client with the handover token"
        Response webSession = Steps.authenticateWithHandoverToken(webFlow, ClientStore.clientA, handoverToken)
        JWTClaimsSet webClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(webFlow, webSession.path("id_token")).JWTClaimsSet

        then: "User and authentication data are carried over into a new session"
        assertThat("Correct audience value", webClaims.audience[0], is(ClientStore.clientA.clientId))
        assertThat("Same subject value", webClaims.subject, is(appClaims.subject))
        assertThat("Same given name value", webClaims.getClaim("given_name"), is(appClaims.getClaim("given_name")))
        assertThat("Same family name value", webClaims.getClaim("family_name"), is(appClaims.getClaim("family_name")))
        assertThat("Same birthdate value", webClaims.getClaim("birthdate"), is(appClaims.getClaim("birthdate")))
        assertThat("Same acr value", webClaims.getClaim("acr"), is(appClaims.getClaim("acr")))
        assertThat("Same amr value", webClaims.getClaim("amr"), is(appClaims.getClaim("amr")))
        assertThat("Handed over session has a new session ID", webClaims.getClaim("sid"), not(is(appClaims.getClaim("sid"))))
        // The initiator claim is covered by "Handed over session tokens identify the app as the initiator".
        // assertThat("Correct initiator", handoverTokenClaims.getClaim("initiator"), equalTo(ClientType.SECURED_APP.toString()))
        // The auth_time claim is covered by "Handed over session keeps the original authentication time"
        // assertThat("Correct authentication time", webClaims.getClaim("auth_time"), equalTo(appClaims.getClaim("auth_time")))

    }

    @PendingFeature(reason = "initiator is absent on a handed over session")
    @Issue("AUT-3087")
    def "Handed over session tokens identify the app as the initiator"() {
        given: "App session handed over to a web client that issues JWT access tokens"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)

        when:
        Response webSession = Steps.authenticateWithHandoverToken(webFlow, ClientStore.clientB, handoverToken)

        then: "The ID token marks the session as initiated by the app"
        JWTClaimsSet webClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(webFlow, webSession.path("id_token")).JWTClaimsSet
        assertThat("Correct initiator in ID token", webClaims.getClaim("initiator"), is("SECURED_APP"))

        and: "The access token marks the session as initiated by the app"
        JWTClaimsSet accessTokenClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(webFlow, webSession.path("access_token")).JWTClaimsSet
        assertThat("Correct initiator in access token", accessTokenClaims.getClaim("initiator"), is("SECURED_APP"))
    }

    @PendingFeature(reason = "auth_time is set to the handover token's issue time instead of being copied from the app session, so the authentication age resets at handover")
    def "Handed over session keeps the original authentication time"() {
        given:
        Response appSession = Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        JWTClaimsSet appClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, appSession.path("id_token")).JWTClaimsSet
        // Make sure there is a detectible time difference.
        sleep(2000)
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)

        when:
        Response webSession = Steps.authenticateWithHandoverToken(webFlow, ClientStore.clientA, handoverToken)

        then:
        JWTClaimsSet webClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(webFlow, webSession.path("id_token")).JWTClaimsSet
        assertThat("Same auth_time value", webClaims.getClaim("auth_time"), is(appClaims.getClaim("auth_time")))
    }

    def "Handed over session can be updated independently of the app session"() {
        given:
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)
        // The handover request rotates the app's refresh token, so capture it only afterwards.
        String appRefreshToken = flow.refreshToken
        Steps.authenticateWithHandoverToken(webFlow, ClientStore.clientA, handoverToken)

        when:
        Response webUpdate = Steps.tryUpdateSession(webFlow, ClientStore.clientA)
        Response appUpdate = Steps.tryUpdateSession(flow, ClientStore.mockSecuredApp, [refresh_token: appRefreshToken])

        then:
        assertThat("Web session update succeeds", webUpdate.statusCode, is(HttpStatus.SC_OK))
        assertThat("App session update succeeds", appUpdate.statusCode, is(HttpStatus.SC_OK))
    }

    def "Handed over session cannot be updated once the original authentication exceeds the client's window"() {
        given: "App authentication that is about to reach the end of the target client's handover window"
        Response appSession = Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        JWTClaimsSet appClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, appSession.path("id_token")).JWTClaimsSet
        // The handover must complete inside this window.
        long remainingSeconds = 10
        long windowSeconds = Utils.parseDuration(ClientStore.clientA.securedAppSessionMaxDuration).toSeconds()
        SqlQueries.ageLoginAuthentication(
                sql, appClaims.getClaim("sid") as String,
                "${windowSeconds - remainingSeconds} seconds")

        and: "Session handed over to a web client while still inside the window"
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)
        Steps.authenticateWithHandoverToken(webFlow, ClientStore.clientA, handoverToken)

        when: "The window lapses, while the handed over session itself is only seconds old"
        sleep((remainingSeconds) * 1000)
        Response webUpdate = Steps.tryUpdateSession(webFlow, ClientStore.clientA)

        then: "The handed over session is bounded by the client's window from the original authentication"
        // TODO: assert expected failure instead of not OK.
        assertThat("Web session update is refused", webUpdate.statusCode, not(is(HttpStatus.SC_OK)))
    }

    def "Handed over session can be continued into a second web client"() {
        given: "App session handed over to a web client"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)
        Response webSession = Steps.authenticateWithHandoverToken(webFlow, ClientStore.clientA, handoverToken)
        JWTClaimsSet webClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(webFlow, webSession.path("id_token")).JWTClaimsSet

        when: "Continue the handed over session into a second web client in the same browser"
        Response secondSession = Steps.continueWithExistingSession(webFlow, ClientStore.clientB)

        then: "The session is continued, not restarted"
        assertThat("Correct HTTP status code", secondSession.statusCode, is(HttpStatus.SC_OK))

        and: "The second client joins the same session"
        JWTClaimsSet secondClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(webFlow, secondSession.path("id_token")).JWTClaimsSet
        assertThat("Correct audience value", secondClaims.audience[0], is(ClientStore.clientB.clientId))
        assertThat("Same subject value", secondClaims.subject, is(webClaims.subject))
        assertThat("Same session ID", secondClaims.getClaim("sid"), is(webClaims.getClaim("sid")))
    }

    def "App session logout does not end the handed over web session"() {
        given: "App session handed over to a web client"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)
        Steps.authenticateWithHandoverToken(webFlow, ClientStore.clientA, handoverToken)

        when: "Log out of the app session"
        Steps.logoutSingleClientSession(flow, flow.idToken, ClientStore.mockSecuredApp.postLogoutRedirectUri)

        and: "Update web session"
        Response webUpdate = Steps.tryUpdateSession(webFlow, ClientStore.clientA)

        then: "Handed over web session survives"
        assertThat("Web session can still be updated", webUpdate.statusCode, is(HttpStatus.SC_OK))
    }

    def "Handed over web session logout does not end the app session"() {
        given: "App session handed over to a web client"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)
        String appRefreshToken = flow.refreshToken
        Steps.authenticateWithHandoverToken(webFlow, ClientStore.clientA, handoverToken)

        when: "Log out of the handed over web session"
        Steps.logoutSingleClientSession(webFlow, webFlow.idToken, ClientStore.clientA.postLogoutRedirectUri)

        and: "Update app session"
        Response appUpdate = Steps.tryUpdateSession(flow, ClientStore.mockSecuredApp, [refresh_token: appRefreshToken])

        then: "App session survives"
        assertThat("App session can still be updated", appUpdate.statusCode, is(HttpStatus.SC_OK))
    }

    def "Handover token is still valid after the origin session is terminated"() {
        given: "App session handed over to a web client"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)
        Steps.logoutSingleClientSession(flow, flow.idToken, ClientStore.mockSecuredApp.postLogoutRedirectUri)

        when:
        sleep(5000)
        Response webSession = Steps.authenticateWithHandoverToken(webFlow, ClientStore.clientA, handoverToken)

        then:
        assertThat("Handover is successful", webSession.statusCode, is(HttpStatus.SC_OK))
    }

    def "Authentication with #reason fails"() {
        given:
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        String accessToken = Steps.updateSession(flow, ClientStore.mockSecuredApp, extraParams).path("access_token")

        when:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(webFlow, ClientStore.clientA)
        paramsMap << [(AUTH_HANDOVER_TOKEN_PARAM): accessToken]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(webFlow, paramsMap)
        Response initLogin = Steps.followRedirect(webFlow, oidcAuth)

        then:
        initLogin.then().statusCode(HttpStatus.SC_BAD_REQUEST).body("error", is("USER_INVALID_OIDC_REQUEST"))

        where:
        reason                                                              | extraParams
        "ordinary access token as auth handover token"                      | [:]
        "access token as auth handover token and GovSSO issuer as audience" | [audience: openIdConfiguration.get("issuer")]
    }

    def "Authentication with a forged auth handover token fails"() {
        given: "Token with valid claims, signed with a key that is not GovSSO's"
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(webFlow, ClientStore.clientA)
        paramsMap << [(AUTH_HANDOVER_TOKEN_PARAM): craftForgedHandoverToken()]

        when:
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(webFlow, paramsMap)
        Response initLogin = Steps.followRedirect(webFlow, oidcAuth)

        then:
        initLogin.then().statusCode(HttpStatus.SC_BAD_REQUEST).body("error", is("USER_INVALID_OIDC_REQUEST"))
    }

    @PendingFeature(reason = "Missing token validation before reauthentication")
    @Issue("AUT-3087")
    def "Authentication with unparseable auth handover token is rejected without ending the existing session"() {
        given: "Existing web session"
        Steps.authenticateWithIdCardInGovSso(webFlow, ClientStore.clientA)
        String existingRefreshToken = webFlow.refreshToken

        when: "Forced logout attempt with a garbage token"
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(webFlow, ClientStore.clientB)
        paramsMap << [(AUTH_HANDOVER_TOKEN_PARAM): "random"]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(webFlow, paramsMap)
        Response initLogin = Steps.followRedirect(webFlow, oidcAuth)

        then: "The request is rejected without restarting authentication"
        initLogin.then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body(
                        "error", is("USER_INPUT"),
                        "path", is("/login/init"),
                        "message", is("Ebakorrektne päring."))

        and: "The existing session survives"
        assertThat("Existing session can still be updated",
                Steps.tryUpdateSession(webFlow, ClientStore.clientA, [refresh_token: existingRefreshToken]).statusCode, is(HttpStatus.SC_OK))
    }

    // TODO: slow test
    @Ignore("Slow failing test")
    @PendingFeature(reason = "auth handover token lifetime limit (60s) not implemented")
    def "Auth handover token older than one minute is rejected"() {
        given: "Genuine handover token, older than its 60 second lifetime"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)
        sleep(65_000)

        when:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(webFlow, ClientStore.clientA)
        paramsMap << [(AUTH_HANDOVER_TOKEN_PARAM): handoverToken]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(webFlow, paramsMap)
        Response initLogin = Steps.followRedirect(webFlow, oidcAuth)

        then:
        initLogin.then().statusCode(HttpStatus.SC_BAD_REQUEST).body("error", is("USER_INVALID_OIDC_REQUEST"))
    }

    @PendingFeature(reason = "token is not marked as used, replay is possible")
    def "Auth handover token can only be used once"() {
        given:
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)
        Steps.authenticateWithHandoverToken(webFlow, ClientStore.clientA, handoverToken)

        when: "Reuse the same token in another browser"
        Flow replayFlow = new Flow()
        wireFlow(replayFlow)
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(replayFlow, ClientStore.clientA)
        paramsMap << [(AUTH_HANDOVER_TOKEN_PARAM): handoverToken]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(replayFlow, paramsMap)
        Response initLogin = Steps.followRedirect(replayFlow, oidcAuth)

        then:
        initLogin.then().statusCode(HttpStatus.SC_BAD_REQUEST).body("error", is("USER_INVALID_OIDC_REQUEST"))
    }

    def "Authentication with auth handover token falls back to TARA for #reason"() {
        given:
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)

        when: "Authenticate with a client that cannot receive a handed over session"
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(webFlow, client)
        paramsMap << [(AUTH_HANDOVER_TOKEN_PARAM): handoverToken]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(webFlow, paramsMap)
        Response initLogin = Steps.followRedirect(webFlow, oidcAuth)

        then: "The handover token is ignored and ordinary authentication is started"
        assertThat("Correct HTTP status code", initLogin.statusCode, is(HttpStatus.SC_MOVED_TEMPORARILY))
        assertThat("Redirected to TARA", initLogin.header("location"), containsString(flow.taraService.host))
        assertThat("Login was not accepted with the handover token", initLogin.header("location"), not(containsString("login_verifier")))

        where:
        reason                                                  | client
        "a client that does not allow secured app web sessions" | ClientStore.mockHandoverDisabled
        "a secured app client"                                  | ClientStore.mockSecuredApp
    }

    def "Authentication with auth handover token succeeds within the target client's handover window"() {
        given:
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)

        when: "Hand over immediately, well inside the window"
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(webFlow, ClientStore.mockMinHandoverWindow)
        paramsMap << [(AUTH_HANDOVER_TOKEN_PARAM): handoverToken]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(webFlow, paramsMap)
        Response initLogin = Steps.followRedirect(webFlow, oidcAuth)

        then: "The handover token is accepted without TARA authentication"
        assertThat("Correct HTTP status code", initLogin.statusCode, is(HttpStatus.SC_MOVED_TEMPORARILY))
        assertThat("Login was accepted with the handover token", initLogin.header("location"), containsString("login_verifier"))
    }

    def "Authentication with auth handover token falls back to TARA outside the target client's handover window"() {
        given: "App session authenticated longer ago than the window allows"
        Response appSession = Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        JWTClaimsSet appClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, appSession.path("id_token")).JWTClaimsSet
        // Aging the login - must exceed clients secured_app_session_max_duration.
        SqlQueries.ageLoginAuthentication(
                sql, appClaims.getClaim("sid") as String, "1 hour 1 second")

        and: "Handover token issued from the aged session"
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)

        when:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(webFlow, ClientStore.mockMinHandoverWindow)
        paramsMap << [(AUTH_HANDOVER_TOKEN_PARAM): handoverToken]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(webFlow, paramsMap)
        Response initLogin = Steps.followRedirect(webFlow, oidcAuth)

        then: "The handover token is ignored and ordinary authentication is started"
        assertThat("Correct HTTP status code", initLogin.statusCode, is(HttpStatus.SC_MOVED_TEMPORARILY))
        assertThat("Redirected to TARA", initLogin.header("location"), containsString(flow.taraService.host))
        assertThat("Login was not accepted with the handover token", initLogin.header("location"), not(containsString("login_verifier")))
    }

    def "Handed over session cannot be continued into a client whose handover window the authentication exceeds"() {
        given: "App session authenticated two hours ago"
        Response appSession = Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        JWTClaimsSet appClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, appSession.path("id_token")).JWTClaimsSet
        SqlQueries.ageLoginAuthentication(
                sql, appClaims.getClaim("sid") as String, "2 hours")

        and: "Handed over to a client whose window is wide enough to accept it"
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)
        Steps.authenticateWithHandoverToken(webFlow, ClientStore.clientA, handoverToken)

        when: "Continue the handed over session into a client with a one hour window"
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(webFlow, ClientStore.mockMinHandoverWindow)
        Response initLogin = Steps.followRedirect(webFlow, oidcAuth)

        then: "The session is not continued, ordinary authentication is required instead"
        assertThat("Correct HTTP status code", initLogin.statusCode, is(HttpStatus.SC_MOVED_TEMPORARILY))
        assertThat("Session was not continued", initLogin.header("location"), not(containsString("login_verifier")))
    }

    def "Handed over session cannot be continued into a client that does not allow secured app web sessions"() {
        given: "App session handed over to a web client"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)
        Steps.authenticateWithHandoverToken(webFlow, ClientStore.clientA, handoverToken)

        when: "Continue the handed over session into a client that does not allow handover"
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(webFlow, ClientStore.mockHandoverDisabled)
        Response initLogin = Steps.followRedirect(webFlow, oidcAuth)

        then: "The session is not continued, ordinary authentication is required instead"
        assertThat("Correct HTTP status code", initLogin.statusCode, is(HttpStatus.SC_MOVED_TEMPORARILY))
        assertThat("Session was not continued", initLogin.header("location"), not(containsString("login_verifier")))
    }


    /**
     * Builds a handover token whose claims are valid but signed with a throwaway key.
     */
    private String craftForgedHandoverToken() {
        String issuer = flow.openIdServiceConfiguration.getString("issuer")
        Instant now = Instant.now()
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .issuer(issuer)
                .audience(issuer)
                .subject("EE38001085718")
                .claim("client_id", ClientStore.mockSecuredApp.clientId)
                .claim("scope", AUTH_HANDOVER_SCOPE)
                .claim("acr", "high")
                .claim("amr", ["idcard"])
                .claim("given_name", "JAAK-KRISTJAN")
                .claim("family_name", "JÕEORG")
                .claim("birthdate", "1980-01-08")
                .claim("initiator", ClientType.SECURED_APP.toString())
                .claim("auth_time", now.epochSecond)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(60)))
                .build()

        RSAKey key = new RSAKeyGenerator(2048).keyID("auth-handover-test-key").generate()
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.keyID).build(), claims)
        signedJWT.sign(new RSASSASigner(key))
        return signedJWT.serialize()
    }
}
