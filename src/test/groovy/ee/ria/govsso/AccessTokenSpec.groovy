package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static ee.ria.govsso.OpenIdUtils.isJWT
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.allOf
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.matchesPattern
import static org.hamcrest.Matchers.not
import static org.hamcrest.Matchers.oneOf

@Feature("ACCESS_TOKEN")
class AccessTokenSpec extends GovSsoSpecification {

    static final AUD1 = "https://test1.test/123"
    static final AUD2 = "https://test2.test/123"

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    def "Authentication with access token configured client should return JWT access token with configured expiration time"() {
        given: "Create session"
        Response tokenResponse = Steps.authenticateWithIdCardInGovSso(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl, "access_token")

        when: "Get access token claims"
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.body.jsonPath().get("access_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.getClaim("aud"), equalTo([AUD1, AUD2]))
        assertThat("Default expiration time", tokenResponse.jsonPath().getInt("expires_in"), oneOf(599, 600))
    }

    def "Session update with access token configured client should return JWT access token"() {
        given: "Create session"
        Steps.authenticateWithIdCardInGovSso(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)

        when: "Update session and get new access token claims"
        Response updateSession = Steps.getSessionUpdateResponse(flow, flow.refreshToken, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, "access_token")
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, updateSession.body.jsonPath().get("access_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.getClaim("aud"), equalTo([AUD1, AUD2]))
    }

    def "Continue session with access token configured client should return JWT access token"() {
        given: "Create session"
        Steps.authenticateWithIdCardInGovSso(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)

        when: "Continue session and get new access token claims"
        Response continueSession = Steps.continueWithExistingSession(flow)
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, continueSession.body.jsonPath().get("access_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.getClaim("aud"), equalTo([AUD1, AUD2]))
    }

    def "Access token audience should hold only audience value specified in authorization request: #audience"() {
        given: "Create session with specified audience"
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        paramsMap << [audience: audience]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response tokenRequest = Steps.followRedirectsToClientApplication(flow, taraAuthentication, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl, "access_token")

        when: "Get access token claims"
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, tokenRequest.body.jsonPath().get("access_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.getClaim("aud"), equalTo([audience]))

        where:
        audience      | _
        AUD1          | _
        AUD1 + "/"    | _
        AUD1 + "/456" | _
    }

    def "Access token audience should hold only audience value requested in authorization request after session update"() {
        given: "Create session with specified audience"
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        paramsMap << [audience: AUD1]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Steps.followRedirectsToClientApplication(flow, taraAuthentication, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl, "access_token")

        when: "Update session and get access token claims"
        Response updateSession = Steps.getSessionUpdateResponse(flow, flow.refreshToken, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, "access_token")
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, updateSession.body.jsonPath().get("access_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.getClaim("aud"), equalTo([AUD1]))
    }

    def "Authorization request should fail if request holds non-registered audience value: #audience"() {
        when: "Request authorization with not registered audience parameter value"
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        paramsMap << [audience: audience]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        then:
        assertThat("Correct HTTP code", oidcAuth.statusCode(), is(303))
        assertThat("Correct OIDC error", oidcAuth.header("location"), allOf(containsString("Requested+audience+"), containsString("+has+not+been+whitelisted+by+the+OAuth+2.0+Client")))

        where:
        audience                      | _
        "https://not-registered.test" | _
        "https://test1.test/"         | _
        "https://test.test/123"       | _
        "test1.test/123"              | _
    }

    def "Access token should hold correct values with scope: openid"() {
        given: "Create session"
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl, "access_token")

        when: "Get access token claims"
        JWTClaimsSet claimsAccessToken = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, createSession.body.jsonPath().get("access_token")).JWTClaimsSet
        JWTClaimsSet claimsIDToken = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, createSession.body.jsonPath().get("id_token")).JWTClaimsSet

        then:
        Set expectedClaims = [
                "acr", "amr", "aud", "birthdate", "client_id",
                "exp", "family_name", "given_name", "iat",
                "iss", "jti", "sub"
        ]
        assertThat("JWT has only expected claims", claimsAccessToken.claims.keySet(), is(expectedClaims))
        assertThat("Jti claim exists", claimsAccessToken.getJWTID(), matchesPattern("([a-f0-9]{8}(-[a-f0-9]{4}){4}[a-f0-9]{8})"))
        assertThat("Access token jti claim is unique from ID token jti", claimsAccessToken.getJWTID(), not(is(claimsIDToken.getJWTID())))
        assertThat("Correct issuer", claimsAccessToken.issuer, is(flow.openIdServiceConfiguration.get("issuer")))
        assertThat("Correct client ID", claimsAccessToken.getClaim("client_id"), is(flow.clientId))
        assertThat("Correct audience", claimsAccessToken.audience, is([AUD1, AUD2]))
        assertThat("Correct issued at time", Math.abs(new Date().time - claimsAccessToken.getDateClaim("iat").time) < 10000L)
        assertThat("Correct expiration time", claimsAccessToken.expirationTime.time - claimsAccessToken.getDateClaim("iat").time, oneOf(600000L, 601000L))
        assertThat("Correct authentication method", claimsAccessToken.getClaim("amr"), is(["idcard"]))
        assertThat("Correct subject claim", claimsAccessToken.subject, is("EE38001085718"))
        assertThat("Correct date of birth", claimsAccessToken.getClaim("birthdate"), is("1980-01-08"))
        assertThat("Correct given name", claimsAccessToken.getClaim("given_name"), is("JAAK-KRISTJAN"))
        assertThat("Correct family name", claimsAccessToken.getClaim("family_name"), is("JÕEORG"))
        assertThat("Correct LoA level", claimsAccessToken.getClaim("acr"), is("high"))
    }

    def "Access token should hold correct values with scope: openid phone"() {
        given: "Create session"
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        paramsMap << [scope: "openid phone"]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", initLogin)
        Response token = Steps.followRedirectsToClientApplication(flow, taraAuthentication, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl, "access_token")

        when: "Get access token claims"
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, token.jsonPath().get("access_token")).JWTClaimsSet

        then:
        Set expectedClaims = [
                "acr", "amr", "aud", "birthdate", "client_id",
                "exp", "family_name", "given_name", "iat",
                "iss", "jti", "phone_number", "phone_number_verified",
                "sub"
        ]
        assertThat("JWT has only expected claims", claims.claims.keySet(), equalTo(expectedClaims))
        assertThat("Correct phone_number claim", claims.getClaim("phone_number"), equalTo("+37269100366"))
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
