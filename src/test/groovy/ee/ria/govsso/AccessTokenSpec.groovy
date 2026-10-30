package ee.ria.govsso

import com.nimbusds.jwt.JWTClaimsSet
import ee.ria.govsso.model.Client
import ee.ria.govsso.model.ClientType
import io.qameta.allure.Feature
import io.restassured.response.Response
import org.apache.http.HttpStatus

import static ee.ria.govsso.OpenIdUtils.isJWT
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

@Feature("ACCESS_TOKEN")
class AccessTokenSpec extends GovSsoOidcSpecification {

    def "Authentication with access token configured client should return JWT access token with configured expiration time"() {
        given: "Create session"
        Response tokenResponse = Steps.authenticateWithIdCardInGovSso(flow, ClientStore.clientB, "access_token")

        when: "Get access token claims"
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.body.path("access_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience, containsInAnyOrder(ClientStore.clientB.accessTokenAudienceUris as String[]))
        assertThat("Default expiration time", tokenResponse.jsonPath().getInt("expires_in"), oneOf(599, 600))
    }

    def "Session update with access token configured client should return JWT access token"() {
        given: "Create session"
        Client client = ClientStore.clientB
        Steps.authenticateWithIdCardInGovSso(flow, client, "access_token")

        when: "Update session and get new access token claims"
        Response updateSession = Steps.updateSession(flow, client)
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, updateSession.body.path("access_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience, containsInAnyOrder(client.accessTokenAudienceUris as String[]))
    }

    def "Continue session with access token configured client should return JWT access token"() {
        given: "Create session"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.clientB, "access_token")

        when: "Continue session and get new access token claims"
        Response continueSession = Steps.continueWithExistingSession(flow)
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, continueSession.body.path("access_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience, containsInAnyOrder(ClientStore.clientB.accessTokenAudienceUris as String[]))
    }

    def "Access token audience should hold only audience value specified in authorization request: #audience"() {
        given: "Create session with specified audience"
        Client client = ClientStore.clientB
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, client)
        paramsMap << [audience: audience]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response tokenRequest = Steps.followRedirectsToClientApplication(flow, taraAuthentication, client, "access_token")

        when: "Update session"
        Response updateSession = Steps.updateSession(flow, client)

        then:
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, tokenRequest.body.path("access_token")).JWTClaimsSet
        JWTClaimsSet updatedClaims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, updateSession.body.path("access_token")).JWTClaimsSet
        assertThat("Correct audience", claims.getClaim("aud"), equalTo([audience]))
        assertThat("Correct audience after session update", updatedClaims.getClaim("aud"), equalTo([audience]))

        where:
        audienceSuffix << ["", "/", "/456"]
        audience = ClientStore.clientB.accessTokenAudienceUris[0] + audienceSuffix
    }

    def "Authorization request should fail if request holds non-registered audience value: #audience"() {
        when: "Request authorization with not registered audience parameter value"
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, ClientStore.clientB)
        paramsMap << [audience: audience]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        then:
        assertThat("Correct HTTP code", oidcAuth.statusCode, is(HttpStatus.SC_SEE_OTHER))
        assertThat("Correct OIDC error", oidcAuth.header("location"), allOf(containsString("Requested+audience+"), containsString("+has+not+been+whitelisted+by+the+OAuth+2.0+Client")))

        where:
        audience                      | _
        "https://not-registered.test" | _
        "https://test1.test/"         | _
        "https://test.test/123"       | _
        "test1.test/123"              | _
    }

    def "Authorization request should fail if request holds the auth handover audience"() {
        when: "Request authorization with GovSSO issuer as audience"
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, ClientStore.mockSecuredApp)
        paramsMap << [audience: flow.openIdServiceConfiguration.get("issuer")]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        then:
        assertThat("Correct HTTP code", oidcAuth.statusCode, is(HttpStatus.SC_SEE_OTHER))
        assertThat("Correct OIDC error", oidcAuth.header("location"), allOf(containsString("error=invalid_request"),
                containsString("Requested+audience+"), containsString("+has+not+been+whitelisted+by+the+OAuth+2.0+Client")))
    }

    def "Session update should fail if request holds the auth handover audience #reason"() {
        given: "Create session"
        Steps.authenticateWithIdCardInGovSso(flow, client)
        String issuer = flow.openIdServiceConfiguration.get("issuer")

        when: "Update session with GovSSO issuer as audience"
        Response response = Steps.tryUpdateSession(flow, client, [audience: issuer] + extraParams)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(HttpStatus.SC_BAD_REQUEST))
        assertThat("Correct error", response.jsonPath().getString("error"), is("invalid_request"))
        assertThat("Correct error description", response.jsonPath().getString("error_description"),
                containsString("Requested audience '${issuer}' has not been whitelisted by the OAuth 2.0 Client.".toString()))

        and: "The rejected request did not consume the refresh token"
        Response retry = Steps.tryUpdateSession(flow, client)
        assertThat("Session update succeeds with the same refresh token", retry.statusCode, is(HttpStatus.SC_OK))

        where:
        reason                                         | client                     | extraParams
        "without scope"                                | ClientStore.mockSecuredApp | [:]
        "with scope 'openid'"                          | ClientStore.mockSecuredApp | [scope: "openid"]
        "with empty scope"                             | ClientStore.mockSecuredApp | [scope: ""]
        "for a client without the handover capability" | ClientStore.clientA        | [:]
    }

    def "Access token for client type #clientType should hold correct values with scope: openid"() {
        given: "Create session"
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow, client, "access_token")

        when: "Get access token claims"
        JWTClaimsSet claimsAccessToken = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, createSession.body.path("access_token")).JWTClaimsSet
        JWTClaimsSet claimsIDToken = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, createSession.body.path("id_token")).JWTClaimsSet

        then:
        Set expectedClaims = [
                "acr", "amr", "aud", "birthdate", "client_id",
                "exp", "family_name", "given_name", "iat",
                "iss", "jti", "sub"
        ]
        if (clientType != ClientType.DEFAULT) {
            expectedClaims += ["auth_time", "initiator"]
        }

        assertThat("JWT has only expected claims", claimsAccessToken.claims.keySet(), is(expectedClaims))
        assertThat("Jti claim exists", claimsAccessToken.getJWTID(), matchesPattern("([a-f0-9]{8}(-[a-f0-9]{4}){4}[a-f0-9]{8})"))
        assertThat("Access token jti claim is unique from ID token jti", claimsAccessToken.getJWTID(), not(is(claimsIDToken.getJWTID())))
        assertThat("Correct issuer", claimsAccessToken.issuer, is(flow.openIdServiceConfiguration.get("issuer")))
        assertThat("Correct client ID", claimsAccessToken.getClaim("client_id"), is(flow.clientId))
        assertThat("Correct audience", claimsAccessToken.audience, containsInAnyOrder(client.accessTokenAudienceUris as String[]))
        assertThat("Correct issued at time", Math.abs(new Date().time - claimsAccessToken.getDateClaim("iat").time) < 10000L)
        assertThat("Correct expiration time", claimsAccessToken.expirationTime.time - claimsAccessToken.getDateClaim("iat").time, oneOf(600000L, 601000L))
        assertThat("Correct authentication method", claimsAccessToken.getClaim("amr"), is(["idcard"]))
        assertThat("Correct subject claim", claimsAccessToken.subject, is(claimsIDToken.subject))
        assertThat("Correct date of birth", claimsAccessToken.getClaim("birthdate"), is(claimsIDToken.getClaim("birthdate")))
        assertThat("Correct given name", claimsAccessToken.getClaim("given_name"), is(claimsIDToken.getClaim("given_name")))
        assertThat("Correct family name", claimsAccessToken.getClaim("family_name"), is(claimsIDToken.getClaim("family_name")))
        assertThat("Correct LoA level", claimsAccessToken.getClaim("acr"), is(claimsIDToken.getClaim("acr")))
        if (clientType != ClientType.DEFAULT) {
            assertThat("Correct authentication time", claimsAccessToken.getClaim("auth_time"), is(claimsIDToken.getClaim("auth_time")))
            assertThat("Correct initiator", claimsAccessToken.getClaim("initiator"), is(claimsIDToken.getClaim("initiator")))
        }

        where:
        clientType             | client
        ClientType.DEFAULT     | ClientStore.clientB
        ClientType.SECURED_APP | ClientStore.mockSecuredApp
    }

    def "Access token should hold correct values with scope: openid phone"() {
        given: "Create session"
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, ClientStore.clientB)
        paramsMap << [scope: "openid phone"]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "59100366", initLogin)
        Response token = Steps.followRedirectsToClientApplication(flow, taraAuthentication, ClientStore.clientB, "access_token")

        when: "Get access token claims"
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, token.path("access_token")).JWTClaimsSet

        then:
        Set expectedClaims = [
                "acr", "amr", "aud", "birthdate", "client_id",
                "exp", "family_name", "given_name", "iat",
                "iss", "jti", "phone_number", "phone_number_verified",
                "sub"
        ]
        assertThat("JWT has only expected claims", claims.claims.keySet(), equalTo(expectedClaims))
        assertThat("Correct phone_number claim", claims.getClaim("phone_number"), equalTo("+37259100366"))
        assertThat("Correct phone_number_verified claim exists", claims.getClaim("phone_number_verified"), equalTo(true))
    }

    def "Access_token for a client with no access token configuration should hold non-JWT value and default expiration time"() {
        when: "Receive token response"
        Response tokenResponse = Steps.authenticateWithIdCardInGovSso(flow)

        then:
        assertThat("Access token is not JWT", isJWT(tokenResponse.jsonPath().getString("access_token")), is(false))
        assertThat("Default expiration time", tokenResponse.jsonPath().getInt("expires_in"), oneOf(0, 1))
    }
}
