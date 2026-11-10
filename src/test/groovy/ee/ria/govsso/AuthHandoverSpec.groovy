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
import ee.ria.govsso.model.ErrorMessage
import ee.ria.govsso.model.HydraError
import ee.ria.govsso.util.ErrorValidator
import ee.ria.govsso.util.HydraErrorValidator
import io.qameta.allure.Feature
import io.restassured.response.Response
import org.apache.http.HttpStatus
import org.spockframework.runtime.model.parallel.ExecutionMode
import spock.lang.Execution
import spock.lang.Tag

import java.time.Duration
import java.time.Instant

import static ee.ria.govsso.Steps.AUTH_HANDOVER_SCOPE
import static ee.ria.govsso.util.HydraErrorValidator.HINT_TOKEN_VALIDATION_FAILED
import static ee.ria.govsso.util.HydraErrorValidator.notWhitelisted
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
                "aud", "client_id", "exp", "iat", "iss", "jti", "scope", "sid"
        ]

        then: "Required claims are present and match"
        assertThat("JWT has only expected claims", handoverTokenClaims.claims.keySet(), equalTo(expectedClaims))
        assertThat("Correct JWT ID claim exists", handoverTokenClaims.JWTID, matchesPattern("([a-f0-9]{8}(-[a-f0-9]{4}){4}[a-f0-9]{8})"))
        assertThat("Correct issuer", handoverTokenClaims.issuer, equalTo(flow.openIdServiceConfiguration.get("issuer")))
        assertThat("Correct audience", handoverTokenClaims.audience, equalTo([flow.openIdServiceConfiguration.get("issuer")]))
        assertThat("Correct scope", handoverTokenClaims.getClaim("scope"), equalTo(AUTH_HANDOVER_SCOPE))
        assertThat("Correct client_id", handoverTokenClaims.getClaim("client_id"), equalTo(ClientStore.mockSecuredApp.clientId))
        assertThat("Correct session id", handoverTokenClaims.getClaim("sid"), equalTo(appClaims.getClaim("sid")))
    }

    def "Auth handover token has a 60 second lifetime"() {
        given: "Create (app) session with SECURED_APP client"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)

        when: "Request auth handover token"
        Response tokenResponse = Steps.getHandoverTokenResponse(flow, ClientStore.mockSecuredApp)
        JWTClaimsSet claims = SignedJWT.parse(tokenResponse.path("access_token") as String).JWTClaimsSet

        then:
        // Handover token follows Hydra approach for other tokens, where the timing can vary due to rounding used in times.
        assertThat("Correct expires_in", tokenResponse.jsonPath().getInt("expires_in"), oneOf(59, 60))
        assertThat("Correct lifetime", claims.expirationTime.time - claims.issueTime.time, oneOf(60_000L, 61_000L))
    }

    def "Auth handover token request fails when #reason"() {
        given: "Create (app) session with SECURED_APP client"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)

        // extraParams overrides the correct audience and scope that tryGetHandoverToken supplies.
        when: "Request auth handover token"
        Response tokenResponse = Steps.tryGetHandoverToken(flow, ClientStore.mockSecuredApp, extraParams)

        then:
        HydraErrorValidator.validate(tokenResponse, expectedError, hint)

        where:
        reason                        | extraParams                                        || expectedError                   | hint
        "refresh token is invalid"    | [refresh_token: Utils.generateOryToken("ory_rt_")] || HydraError.INVALID_GRANT        | ""
        "scope contains other scopes" | [scope: "openid " + AUTH_HANDOVER_SCOPE]           || HydraError.TOKEN_HOOK_REJECTION | "Auth handover token request requested scopes can contain only auth_handover scope"
        "audience is empty"           | [audience: ""]                                     || HydraError.TOKEN_HOOK_REJECTION | "Auth handover granted audience can contain only the configured GovSSO base URL"
        "audience is omitted"         | [audience: null]                                   || HydraError.TOKEN_HOOK_REJECTION | "Auth handover granted audience can contain only the configured GovSSO base URL"
    }

    def "Auth handover token request fails when audience #reason"() {
        given: "Create (app) session with SECURED_APP client"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)

        when: "Request auth handover token"
        Response tokenResponse = Steps.tryGetHandoverToken(flow, ClientStore.mockSecuredApp, [audience: audience])

        then: "Hydra names the first requested audience that is not whitelisted, which in every case is the first one"
        HydraErrorValidator.validate(tokenResponse, HydraError.INVALID_REQUEST, notWhitelisted(audience.split(" ").first()))

        where:
        reason                                | audience
        "is not GovSSO's base URL"            | "https://not.govsso/"
        "is issuer without trailing slash"    | openIdConfiguration.getString("issuer").replaceAll('/$', "")
        "is issuer with extra trailing slash" | openIdConfiguration.getString("issuer") + "/"
        "is issuer in upper case"             | openIdConfiguration.getString("issuer").toUpperCase()
        "is a path below issuer"              | openIdConfiguration.getString("issuer") + "some/path"
        "contains extra URL(s)"               | ([openIdConfiguration.getString("issuer")] + ClientStore.mockSecuredApp.accessTokenAudienceUris).join(" ")
        // TODO: Allure logging can't handle lists in formParams, causing the request to fail - needs a solution
//        "contains extra URL(s)"               | ClientStore.mockSecuredApp.accessTokenAudienceUris
    }

    def "Auth handover token request fails for a client without the handover capability configured"() {
        given: "Create session with DEFAULT client"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.clientA)

        when:
        Response tokenResponse = Steps.tryGetHandoverToken(flow, ClientStore.clientA)

        then:
        HydraErrorValidator.validate(tokenResponse, HydraError.INVALID_REQUEST, notWhitelisted(flow.openIdServiceConfiguration.get("issuer") as String))
    }

    def "Auth handover scope cannot be requested in the authentication request"() {
        when: "Authentication request carries the handover scope, with a client that has it configured"
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithScope(flow, ClientStore.mockSecuredApp, "openid " + AUTH_HANDOVER_SCOPE)
        Response initLogin = Steps.followRedirect(flow, oidcAuth)

        then: "Request is rejected"
        ErrorValidator.validate(initLogin, ErrorMessage.USER_INPUT, "/login/init")
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
    }

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

    def "Handed over session carries the phone number when the phone scope is granted"() {
        given: "App session authenticated with Mobile-ID and phone scope"
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithScope(flow, ClientStore.mockSecuredApp, "openid phone")
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "59100366", initLogin)
        Steps.followRedirectsToClientApplication(flow, taraAuthentication, ClientStore.mockSecuredApp)
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)

        when: "Authenticate with the handover token in a web client that requests the phone scope"
        Map paramsMap = OpenIdUtils.getAuthorizationParametersWithScope(webFlow, ClientStore.clientA, "openid phone")
        paramsMap << [(Steps.AUTH_HANDOVER_TOKEN_PARAM): handoverToken]
        Response webOidcAuth = Steps.startAuthenticationInSsoOidcWithParams(webFlow, paramsMap)
        Response webInitLogin = Steps.followRedirect(webFlow, webOidcAuth)
        Response webSession = Steps.followRedirectsToClientApplicationWithExistingSession(webFlow, webInitLogin, ClientStore.clientA)

        then:
        JWTClaimsSet webClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(webFlow, webSession.path("id_token")).JWTClaimsSet
        assertThat("Correct phone_number claim", webClaims.getClaim("phone_number"), is("+37259100366"))
        assertThat("Correct phone_number_verified claim", webClaims.getClaim("phone_number_verified"), is(true))
    }

    def "Handed over session keeps the original authentication time"() {
        given:
        Response appSession = Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        JWTClaimsSet appClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, appSession.path("id_token")).JWTClaimsSet
        // Make sure there is a detectible time difference.
        sleep(2000)
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)

        when: "Authenticate with the handover token in a web client that issues JWT access tokens"
        Response webSession = Steps.authenticateWithHandoverToken(webFlow, ClientStore.clientB, handoverToken)

        then:
        JWTClaimsSet idTokenClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(webFlow, webSession.path("id_token")).JWTClaimsSet
        JWTClaimsSet accessTokenClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(webFlow, webSession.path("access_token")).JWTClaimsSet
        assertThat("Same auth_time in ID token", idTokenClaims.getClaim("auth_time"), is(appClaims.getClaim("auth_time")))
        assertThat("Same auth_time in access token", accessTokenClaims.getClaim("auth_time"), is(appClaims.getClaim("auth_time")))

        when: "Update the handed over session"
        Response webUpdate = Steps.updateSession(webFlow, ClientStore.clientB)

        then:
        JWTClaimsSet updatedIdTokenClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(webFlow, webUpdate.path("id_token")).JWTClaimsSet
        JWTClaimsSet updatedAccessTokenClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(webFlow, webUpdate.path("access_token")).JWTClaimsSet
        assertThat("Same auth_time in updated ID token", updatedIdTokenClaims.getClaim("auth_time"), is(appClaims.getClaim("auth_time")))
        assertThat("Same auth_time in updated access token", updatedAccessTokenClaims.getClaim("auth_time"), is(appClaims.getClaim("auth_time")))
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

    def "Auth handover request does not change the app session's own tokens"() {
        given:
        Response appSession = Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        JWTClaimsSet beforeHandover = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(
                flow, appSession.path("access_token")).JWTClaimsSet
        // The handover request rotates the app's refresh token, leaving this one behind.
        String staleRefreshToken = flow.refreshToken

        when: "Request a handover token and update the app session twice"
        Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)
        Response firstUpdate = Steps.updateSession(flow, ClientStore.mockSecuredApp)
        Response secondUpdate = Steps.updateSession(flow, ClientStore.mockSecuredApp)

        then: "The audience of the handover request has not leaked into the app session's access tokens"
        JWTClaimsSet firstClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(
                flow, firstUpdate.path("access_token")).JWTClaimsSet
        JWTClaimsSet secondClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(
                flow, secondUpdate.path("access_token")).JWTClaimsSet
        assertThat("Audience unchanged by the handover request", firstClaims.audience, equalTo(beforeHandover.audience))
        assertThat("Audience unchanged by every following update", secondClaims.audience, equalTo(beforeHandover.audience))

        and: "Neither has its scope"
        assertThat("Correct scope value", firstUpdate.jsonPath().getString("scope"), is("openid"))
        assertThat("Correct scope value", secondUpdate.jsonPath().getString("scope"), is("openid"))
        assertThat("Access token has no scope claim", firstClaims.claims.keySet(), not(hasItem("scope")))
        assertThat("Access token has no scope claim", secondClaims.claims.keySet(), not(hasItem("scope")))

        and: "The refresh token that the handover request rotated away is no longer accepted"
        Response reuse = Steps.tryUpdateSession(flow, ClientStore.mockSecuredApp, [refresh_token: staleRefreshToken])
        HydraErrorValidator.validate(reuse, HydraError.TOKEN_INACTIVE, HINT_TOKEN_VALIDATION_FAILED)
    }

    def "Auth handover can be repeated on the same app session"() {
        given:
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        String issuer = flow.openIdServiceConfiguration.get("issuer")

        when: "Request a second auth handover token from the same app session"
        JWTClaimsSet firstHandoverToken = SignedJWT.parse(
                Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)).JWTClaimsSet
        String secondToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)
        JWTClaimsSet secondHandoverToken = SignedJWT.parse(secondToken).JWTClaimsSet

        then: "Both handover tokens are addressed to GovSSO"
        assertThat("Correct audience in the first handover token", firstHandoverToken.audience, is([issuer]))
        assertThat("Correct scope in the first handover token", firstHandoverToken.getClaim("scope"), is(AUTH_HANDOVER_SCOPE))
        assertThat("Correct audience in the second handover token", secondHandoverToken.audience, is([issuer]))
        assertThat("Correct scope in the second handover token", secondHandoverToken.getClaim("scope"), is(AUTH_HANDOVER_SCOPE))

        and: "The second handover token can still create a web session"
        Response webSession = Steps.authenticateWithHandoverToken(webFlow, ClientStore.clientA, secondToken)
        assertThat("Handover is successful", webSession.statusCode, is(HttpStatus.SC_OK))
    }

    def "Handed over session cannot be updated once the original authentication exceeds the client's window"() {
        given: "App authentication that is about to reach the end of the target client's handover window"
        Response appSession = Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        // The handover must complete inside this window.
        long remainingSeconds = 10
        Duration window = Utils.parseDuration(ClientStore.clientA.securedAppSessionMaxDuration)
        ageAppAuthentication(appSession, window.minusSeconds(remainingSeconds))

        and: "Session handed over to a web client while still inside the window"
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)
        Response webSession = Steps.authenticateWithHandoverToken(webFlow, ClientStore.clientA, handoverToken)
        assertThat("Handover is successful", webSession.statusCode, is(HttpStatus.SC_OK))

        when: "The window lapses, while the handed over session itself is only seconds old"
        sleep((remainingSeconds) * 1000)
        Response webUpdate = Steps.tryUpdateSession(webFlow, ClientStore.clientA)

        then: "The handed over session is bounded by the client's window from the original authentication"
        HydraErrorValidator.validate(webUpdate, HydraError.TOKEN_HOOK_REJECTION,
                "Session refresh is not allowed: secured app session is older than client's secured app session max age (${window})")
    }

    def "Handed over session cannot be updated once the handover exceeds the session max duration"() {
        given: "App session handed over to a web client"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)
        Response webSession = Steps.authenticateWithHandoverToken(webFlow, ClientStore.clientA, handoverToken)
        JWTClaimsSet webClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(webFlow, webSession.path("id_token")).JWTClaimsSet

        and: "Handover aged beyond the session max duration, while the app authentication stays inside the client's window"
        SqlQueries.ageAuthHandover(sql, webClaims.getClaim("sid") as String, Duration.ofHours(13))

        when:
        Response webUpdate = Steps.tryUpdateSession(webFlow, ClientStore.clientA)

        then: "The handed over session is bounded by the session max duration from the handover"
        HydraErrorValidator.validate(webUpdate, HydraError.TOKEN_HOOK_REJECTION,
                "Session refresh is not allowed: handed over session is older than session max duration (PT12H)")
    }

    def "Handed over session can be continued into a second web client"() {
        given: "App session handed over to a web client"
        Response appSession = Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        JWTClaimsSet appClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, appSession.path("id_token")).JWTClaimsSet
        // Make sure there is a detectible time difference.
        sleep(2000)
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
        assertThat("App's auth_time value", secondClaims.getClaim("auth_time"), is(appClaims.getClaim("auth_time")))
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

    def "Auth handover token is rejected after the origin session is terminated"() {
        given: "Auth handover token from an app session that is then logged out"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)
        Steps.logoutSingleClientSession(flow, flow.idToken, ClientStore.mockSecuredApp.postLogoutRedirectUri)

        when:
        Response initLogin = Steps.startAuthenticationWithHandoverToken(webFlow, ClientStore.clientA, handoverToken)

        then:
        ErrorValidator.validate(initLogin, ErrorMessage.USER_INPUT)
    }

    def "Authentication with ordinary access token as auth handover token fails"() {
        given:
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        String accessToken = Steps.updateSession(flow, ClientStore.mockSecuredApp).path("access_token")

        when:
        Response initLogin = Steps.startAuthenticationWithHandoverToken(webFlow, ClientStore.clientA, accessToken)

        then:
        ErrorValidator.validate(initLogin, ErrorMessage.USER_INVALID_OIDC_REQUEST)
    }

    def "Authentication with a forged auth handover token fails"() {
        given: "Token with valid claims, signed with a key that is not GovSSO's"
        String forgedToken = craftForgedHandoverToken()

        when:
        Response initLogin = Steps.startAuthenticationWithHandoverToken(webFlow, ClientStore.clientA, forgedToken)

        then:
        ErrorValidator.validate(initLogin, ErrorMessage.USER_INVALID_OIDC_REQUEST)
    }

    def "Authentication with #reason auth handover token is rejected without ending the existing session"() {
        given: "Existing web session"
        Steps.authenticateWithIdCardInGovSso(webFlow, ClientStore.clientA)
        String existingRefreshToken = webFlow.refreshToken

        when: "Forced logout attempt with an invalid token"
        Response initLogin = Steps.startAuthenticationWithHandoverToken(webFlow, ClientStore.clientB, handoverToken)

        then: "The request is rejected without restarting authentication"
        ErrorValidator.validate(initLogin, expectedError, "/login/init")

        and: "The existing session survives"
        assertThat("Existing session can still be updated",
                Steps.tryUpdateSession(webFlow, ClientStore.clientA, [refresh_token: existingRefreshToken]).statusCode, is(HttpStatus.SC_OK))

        where:
        reason        | handoverToken              || expectedError
        "unparseable" | "random"                   || ErrorMessage.USER_INPUT
        "forged"      | craftForgedHandoverToken() || ErrorMessage.USER_INVALID_OIDC_REQUEST
    }

    @Tag("slow")
    @Execution(ExecutionMode.CONCURRENT)
    def "Auth handover token older than one minute is rejected"() {
        given: "Genuine handover token, older than its 60 second lifetime"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)
        JWTClaimsSet claims = SignedJWT.parse(handoverToken).JWTClaimsSet
        long lifetime = claims.expirationTime.time - claims.issueTime.time
        assertThat("Handover token lifetime is at most 61 seconds", lifetime, lessThanOrEqualTo(61_000L))
        sleep(lifetime + 2000)

        when:
        Response initLogin = Steps.startAuthenticationWithHandoverToken(webFlow, ClientStore.clientA, handoverToken)

        then:
        ErrorValidator.validate(initLogin, ErrorMessage.USER_INVALID_OIDC_REQUEST)
    }

    def "Auth handover token can only be used once"() {
        given:
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)
        Response firstUse = Steps.authenticateWithHandoverToken(webFlow, ClientStore.clientA, handoverToken)
        assertThat("First handover is successful", firstUse.statusCode, is(HttpStatus.SC_OK))

        when: "Reuse the same token in another browser"
        Flow replayFlow = new Flow()
        wireFlow(replayFlow)
        Response initLogin = Steps.startAuthenticationWithHandoverToken(replayFlow, ClientStore.clientA, handoverToken)

        then:
        ErrorValidator.validate(initLogin, ErrorMessage.USER_INPUT)
    }

    def "Authentication with auth handover token falls back to TARA for #reason"() {
        given:
        Response appSession = Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        if (appAuthAge != _) {
            ageAppAuthentication(appSession, appAuthAge as Duration)
        }
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)

        when: "Authenticate with a client that cannot receive a handed over session"
        Response initLogin = Steps.startAuthenticationWithHandoverToken(webFlow, client, handoverToken)

        then: "The handover token is ignored and ordinary authentication is started"
        assertThat("Correct HTTP status code", initLogin.statusCode, is(HttpStatus.SC_MOVED_TEMPORARILY))
        assertThat("Redirected to TARA", initLogin.header("location"), containsString(flow.taraService.host))
        assertThat("Login was not accepted with the handover token", initLogin.header("location"), not(containsString("login_verifier")))

        where:
        reason                                                          | client                            | appAuthAge
        "a default client without secured app web sessions allowed"     | ClientStore.mockHandoverDisabled  | _
        "a secured app client without secured app web sessions allowed" | ClientStore.mockSecuredApp        | _
        "an authentication outside the target client's handover window" | ClientStore.mockMinHandoverWindow | Duration.ofHours(1).plusSeconds(1)
    }

    def "Authentication with auth handover token succeeds within the target client's handover window"() {
        given:
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)

        when: "Hand over immediately, well inside the window"
        Response initLogin = Steps.startAuthenticationWithHandoverToken(webFlow, ClientStore.mockMinHandoverWindow, handoverToken)

        then: "The handover token is accepted without TARA authentication"
        assertThat("Correct HTTP status code", initLogin.statusCode, is(HttpStatus.SC_MOVED_TEMPORARILY))
        assertThat("Login was accepted with the handover token", initLogin.header("location"), containsString("login_verifier"))
    }

    def "Handed over session cannot be continued into a client when #reason"() {
        given: "App session handed over to a web client whose window is wide enough to accept it"
        Response appSession = Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        if (appAuthAge != _) {
            ageAppAuthentication(appSession, appAuthAge as Duration)
        }
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)
        Steps.authenticateWithHandoverToken(webFlow, ClientStore.clientA, handoverToken)
        String webRefreshToken = webFlow.refreshToken

        when: "Continue the handed over session into the target client"
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(webFlow, client)
        Response initLogin = Steps.followRedirect(webFlow, oidcAuth)

        then: "The session is not continued, the authentication request is restarted instead"
        assertThat("Correct HTTP status code", initLogin.statusCode, is(HttpStatus.SC_MOVED_TEMPORARILY))
        assertThat("Redirected back to the authorization request", initLogin.header("location"),
                allOf(containsString("/oauth2/auth"),
                        containsString("client_id=" + client.clientId)))

        and: "The browser is no longer carrying a session"
        // The cookie is cleared by being re-sent already expired.
        assertThat("Oidc session cookie is expired",
                initLogin.detailedCookie("__Host-ory_hydra_session").expiryDate, lessThan(new Date()))

        and: "The handed over session is terminated"
        Response webUpdate = Steps.tryUpdateSession(webFlow, ClientStore.clientA, [refresh_token: webRefreshToken])
        HydraErrorValidator.validate(webUpdate, HydraError.INVALID_GRANT)

        where:
        reason                                                    | client                            | appAuthAge
        "it does not allow secured app web sessions"              | ClientStore.mockHandoverDisabled  | _
        "the authentication exceeds the client's handover window" | ClientStore.mockMinHandoverWindow | Duration.ofHours(2)
    }

    def "Handed over session cannot be continued from the continuation view once the authentication exceeds the client's window"() {
        given: "App authentication that is about to reach the end of the target client's handover window"
        Response appSession = Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)
        // The continuation view must be opened inside this window.
        long remainingSeconds = 10
        Duration window = Utils.parseDuration(ClientStore.mockMinHandoverWindow.securedAppSessionMaxDuration)
        ageAppAuthentication(appSession, window.minusSeconds(remainingSeconds))

        and: "Session handed over to a web client"
        String handoverToken = Steps.getHandoverToken(flow, ClientStore.mockSecuredApp)
        Steps.authenticateWithHandoverToken(webFlow, ClientStore.clientA, handoverToken)
        String webRefreshToken = webFlow.refreshToken

        and: "Continuation view opened for the target client while still inside the window"
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(webFlow, ClientStore.mockMinHandoverWindow)
        Response initLogin = Steps.followRedirect(webFlow, oidcAuth)
        assertThat("Continuation view is shown", initLogin.statusCode, is(HttpStatus.SC_OK))

        when: "The window lapses before the continuation is submitted"
        sleep(remainingSeconds * 1000)
        Map formParams = [loginChallenge: webFlow.loginChallenge,
                          _csrf         : initLogin.body.htmlPath().get("**.find {it.@name == '_csrf'}.@value")]
        Response continueSession = Requests.postRequestWithParams(webFlow, webFlow.sessionService.fullContinueSessionUrl, formParams)

        then: "The session is not continued, the authentication request is restarted instead"
        assertThat("Correct HTTP status code", continueSession.statusCode, is(HttpStatus.SC_MOVED_TEMPORARILY))
        assertThat("Redirected back to the authorization request", continueSession.header("location"),
                allOf(containsString("/oauth2/auth"),
                        containsString("client_id=" + ClientStore.mockMinHandoverWindow.clientId)))

        and: "The browser is no longer carrying a session"
        // The cookie is cleared by being re-sent already expired.
        assertThat("Oidc session cookie is expired",
                continueSession.detailedCookie("__Host-ory_hydra_session").expiryDate, lessThan(new Date()))

        and: "The handed over session is terminated"
        Response webUpdate = Steps.tryUpdateSession(webFlow, ClientStore.clientA, [refresh_token: webRefreshToken])
        HydraErrorValidator.validate(webUpdate, HydraError.INVALID_GRANT)
    }

    private void ageAppAuthentication(Response appSession, Duration age) {
        JWTClaimsSet appClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, appSession.path("id_token")).JWTClaimsSet
        SqlQueries.ageLoginAuthentication(sql, appClaims.getClaim("sid") as String, age)
    }

    /**
     * Builds a handover token whose claims are valid but signed with a throwaway key.
     */
    private String craftForgedHandoverToken() {
        String issuer = openIdConfiguration.getString("issuer")
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
