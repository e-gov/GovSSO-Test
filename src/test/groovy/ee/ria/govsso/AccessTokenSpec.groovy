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

    def "Authentication with access token configured client should return JWT access token"() {
        given: "Create session"
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl, "access_token")

        when: "Get access token claims"
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, createSession.body.jsonPath().get("access_token")).getJWTClaimsSet()

        then:
        assertThat("Correct audience", claims.getClaim("aud"), equalTo([AUD1, AUD2]))
    }

    def "Session update with access token configured client should return JWT access token"() {
        given: "Create session"
        Steps.authenticateWithIdCardInGovSso(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)

        when: "Update session and get new access token claims"
        Response updateSession = Steps.getSessionUpdateResponse(flow, flow.refreshToken, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, "access_token")
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, updateSession.body.jsonPath().get("access_token")).getJWTClaimsSet()

        then:
        assertThat("Correct audience", claims.getClaim("aud"), equalTo([AUD1, AUD2]))
    }

    def "Continue session with access token configured client should return JWT access token"() {
        given: "Create session"
        Steps.authenticateWithIdCardInGovSso(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)

        when: "Continue session and get new access token claims"
        Response continueSession = Steps.continueWithExistingSession(flow)
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, continueSession.body.jsonPath().get("access_token")).getJWTClaimsSet()

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
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, tokenRequest.body.jsonPath().get("access_token")).getJWTClaimsSet()

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
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, updateSession.body.jsonPath().get("access_token")).getJWTClaimsSet()

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
        JWTClaimsSet claimsAccessToken = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, createSession.body.jsonPath().get("access_token")).getJWTClaimsSet()
        JWTClaimsSet claimsIDToken = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, createSession.body.jsonPath().get("id_token")).getJWTClaimsSet()

        then:
        Set expectedClaims = [
                "acr", "amr", "aud", "birthdate", "client_id",
                "exp", "ext", "family_name", "given_name", "iat",
                "iss", "jti", "scp", "sub"
        ]
        assertThat("JWT has only expected claims", claimsAccessToken.getClaims().keySet(), equalTo(expectedClaims))
        assertThat("Jti claim exists", claimsAccessToken.getJWTID(), matchesPattern("([a-f0-9]{8}(-[a-f0-9]{4}){4}[a-f0-9]{8})"))
        assertThat("Access token jti claim is unique from ID token jti", claimsAccessToken.getJWTID(), not(is(claimsIDToken.getJWTID())))
        assertThat("Correct issuer", claimsAccessToken.issuer, equalTo(flow.openIdServiceConfiguration.get("issuer")))
        assertThat("Correct client ID", claimsAccessToken.getClaim("client_id"), equalTo(flow.clientId))
        assertThat("Correct audience", claimsAccessToken.audience, equalTo([AUD1, AUD2]))
        assertThat("Correct issued at time", Math.abs(new Date().time - claimsAccessToken.getDateClaim("iat").time) < 10000L)
        assertThat("Correct expiration time", claimsAccessToken.expirationTime.time - claimsAccessToken.getDateClaim("iat").time, equalTo(300000L))
        assertThat("Correct authentication method", claimsAccessToken.getClaim("amr"), equalTo(["idcard"]))
        assertThat("Correct subject claim", claimsAccessToken.subject, equalTo("EE38001085718"))
        assertThat("Correct date of birth", claimsAccessToken.getClaim("birthdate"), equalTo("1980-01-08"))
        assertThat("Correct given name", claimsAccessToken.getClaim("given_name"), equalTo("JAAK-KRISTJAN"))
        assertThat("Correct family name", claimsAccessToken.getClaim("family_name"), equalTo("JÕEORG"))
        assertThat("Correct LoA level", claimsAccessToken.getClaim("acr"), equalTo("high"))
        assertThat("Correct ext.acr claim", claimsAccessToken.getClaim("ext").getAt("acr"), is(claimsAccessToken.getClaim("acr")))
        assertThat("Correct ext.amr claim", claimsAccessToken.getClaim("ext").getAt("amr"), is(claimsAccessToken.getClaim("amr")))
        assertThat("Correct ext.birthdate claim", claimsAccessToken.getClaim("ext").getAt("birthdate"), is(claimsAccessToken.getClaim("birthdate")))
        assertThat("Correct ext.given_name claim", claimsAccessToken.getClaim("ext").getAt("given_name"), is(claimsAccessToken.getClaim("given_name")))
        assertThat("Correct ext.gamily_name claim", claimsAccessToken.getClaim("ext").getAt("family_name"), is(claimsAccessToken.getClaim("family_name")))
        assertThat("Correct scp name", claimsAccessToken.getClaim("scp"), equalTo(["openid"]))
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
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, token.jsonPath().get("access_token")).getJWTClaimsSet()

        then:
        Set expectedClaims = [
                "acr", "amr", "aud", "birthdate", "client_id",
                "exp", "ext", "family_name", "given_name", "iat",
                "iss", "jti", "phone_number", "phone_number_verified",
                "scp", "sub"
        ]
        assertThat("JWT has only expected claims", claims.getClaims().keySet(), equalTo(expectedClaims))
        assertThat("Correct phone_number claim", claims.getClaim("phone_number"), equalTo("+37269100366"))
        assertThat("Correct phone_number_verified claim exists", claims.getClaim("phone_number_verified"), equalTo(true))
    }

    def "Access_token for a client with no access token configuration should hold non-JWT value"() {
        when: "Receive token response"
        Response tokenResponse = Steps.authenticateWithIdCardInGovSso(flow)

        then:
        assertThat("Access token is not JWT", isJWT(tokenResponse.jsonPath().getString("access_token")), is(false))
    }
}
