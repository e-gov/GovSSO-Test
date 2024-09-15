package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.qameta.allure.Step
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.matchesPattern
import static org.hamcrest.Matchers.hasKey
import static org.hamcrest.Matchers.not

import static org.hamcrest.MatcherAssert.assertThat

class OidcIdentityTokenSpec extends GovSsoSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Feature("ID_TOKEN")
    def "Verify ID token response with client_secret_basic configured client"() {
        when: "Create session and request ID token with client_secret_basic"
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)

        then:
        assertThat("Correct token_type value", createSession.jsonPath().getString("token_type"), is("bearer"))
        assertThat("Correct scope value", createSession.jsonPath().getString("scope"), is("openid"))
        assertThat("Access token element exists", createSession.jsonPath().getString("access_token").size() > 32)
        assertThat("Expires in element exists", createSession.jsonPath().getInt("expires_in") <= 1)
        assertThat("ID token element exists", createSession.jsonPath().getString("id_token").size() > 1000)
        assertThat("Refresh token element exists", createSession.jsonPath().getString("refresh_token").size() == 94)
    }

    @Feature("ID_TOKEN")
    def "Verify ID token response with client_secret_post configured client"() {
        given: "Create session"
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, "client-f", "https://clientf.localhost:11443/login/oauth2/code/govsso")
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response consentVerifier = followRedirectsToClientApplication(flow, taraAuthentication)
        String authorizationCode = Utils.getParamValueFromResponseHeader(consentVerifier, "code")

        when: "Request ID token with client_secret_post"
        Response tokenResponse = Requests.webTokenPostRequest(flow, authorizationCode)

        then:
        assertThat("Correct token_type value", tokenResponse.jsonPath().getString("token_type"), is("bearer"))
        assertThat("Correct scope value", tokenResponse.jsonPath().getString("scope"), is("openid"))
        assertThat("Access token element exists", tokenResponse.jsonPath().getString("access_token").size() > 32)
        assertThat("Expires in element exists", tokenResponse.jsonPath().getInt("expires_in") <= 1)
        assertThat("ID token element exists", tokenResponse.jsonPath().getString("id_token").size() > 1000)
        assertThat("Refresh token element exists", tokenResponse.jsonPath().getString("refresh_token").size() == 94)
    }

    @Feature("ID_TOKEN")
    def "Client_secret_post token endpoint request should fail when client has client_secret_basic configuration"() {
        given: "Create session"
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response consentVerifier = followRedirectsToClientApplication(flow, taraAuthentication)
        String authorizationCode = Utils.getParamValueFromResponseHeader(consentVerifier, "code")

        when: "Request ID token with incorrect token authentication method"
        Response tokenResponse = Requests.webTokenPostRequest(flow, authorizationCode, flow.oidcClientA.clientId, flow.oidcClientA.clientSecret, flow.oidcClientA.fullResponseUrl)

        then:
        assertThat("Correct HTTP status", tokenResponse.statusCode, is(401))
        assertThat("Correct error", tokenResponse.jsonPath().getString("error"), is("invalid_client"))
        assertThat("Correct error message", tokenResponse.jsonPath().getString("error_description"), containsString(
                "The OAuth 2.0 Client supports client authentication method 'client_secret_basic', but method 'client_secret_post' was requested."))
    }

    @Feature("ID_TOKEN")
    def "Client_secret_basic token endpoint request should fail when client has client_secret_post configuration"() {
        given: "Create session"
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, "client-f", "https://clientf.localhost:11443/login/oauth2/code/govsso")
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response consentVerifier = followRedirectsToClientApplication(flow, taraAuthentication)
        String authorizationCode = Utils.getParamValueFromResponseHeader(consentVerifier, "code")

        when: "Request ID token with incorrect token authentication method"
        Response tokenResponse = Requests.webTokenBasicRequest(flow,
                authorizationCode,
                "client-f",
                "secretf",
                "https://clientf.localhost:11443/login/oauth2/code/govsso")

        then:
        assertThat("Correct HTTP status", tokenResponse.statusCode, is(401))
        assertThat("Correct error", tokenResponse.jsonPath().getString("error"), is("invalid_client"))
        assertThat("Correct error message", tokenResponse.jsonPath().getString("error_description"), containsString(
                "The OAuth 2.0 Client supports client authentication method 'client_secret_post', but method 'client_secret_basic' was requested."))
    }

    @Feature("ID_TOKEN")
    def "Verify ID token response when scope includes phone"() {
        expect:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap << [scope: "openid phone"]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", initLogin)
        Response token = Steps.followRedirectsToClientApplication(flow, taraAuthentication)

        assertThat("Correct token_type value", token.jsonPath().getString("token_type"), is("bearer"))
        assertThat("Correct scope value", token.jsonPath().getString("scope"), is("openid phone"))
        assertThat("Access token element exists", token.jsonPath().getString("access_token").size() > 32)
        assertThat("Expires in element exists", token.jsonPath().getInt("expires_in") <= 1)
        assertThat("ID token element exists", token.jsonPath().getString("id_token").size() > 1000)
    }

    @Feature("ID_TOKEN")
    def "Verify ID token mandatory elements"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, createSession.jsonPath().get("id_token")).JWTClaimsSet

        Set expectedClaims = [
                "acr", "amr", "at_hash", "aud", "auth_time",
                "birthdate", "exp", "family_name", "given_name", "iat",
                "iss", "jti", "nonce", "rat", "sid", "sub"
        ]
        assertThat("JWT has only expected claims", claims.claims.keySet(), equalTo(expectedClaims))
        assertThat("Correct JWT ID claim exists", claims.JWTID, matchesPattern("([a-f0-9]{8}(-[a-f0-9]{4}){4}[a-f0-9]{8})"))
        assertThat("Correct nonce", claims.getClaim("nonce"), equalTo(flow.nonce))
        assertThat("Correct issuer", claims.issuer, equalTo(flow.openIdServiceConfiguration.get("issuer")))
        assertThat("Correct audience", claims.audience[0], equalTo(flow.oidcClientA.clientId))
        Date date = new Date()
        assertThat("Correct authentication time", Math.abs(date.time - claims.getDateClaim("auth_time").time) < 10000L)
        assertThat("Correct issued at time", Math.abs(date.time - claims.getDateClaim("iat").time) < 10000L)
        assertThat("Correct expiration time", claims.expirationTime.time - claims.getDateClaim("iat").time, equalTo(900000L))
        assertThat("Correct authentication method", claims.getClaim("amr"), equalTo(["idcard"]))
        assertThat("Correct subject claim", claims.subject, equalTo("EE38001085718"))
        assertThat("Correct date of birth", claims.getClaim("birthdate"), equalTo("1980-01-08"))
        assertThat("Correct given name", claims.getClaim("given_name"), equalTo("JAAK-KRISTJAN"))
        assertThat("Correct family name", claims.getClaim("family_name"), equalTo("JÕEORG"))
        assertThat("Correct LoA level", claims.getClaim("acr"), equalTo("high"))
        assertThat("Correct UUID pattern for session ID", claims.getStringClaim("sid"), matchesPattern("([a-f0-9]{8}(-[a-f0-9]{4}){4}[a-f0-9]{8})"))
        assertThat("Claim phone_number does not exist", claims.claims, not(hasKey("phone_number")))
        assertThat("Claim phone_number_verified does not exist", claims.claims, not(hasKey("phone_number_verified")))
        assertThat("Correct at_hash claim exists", claims.getStringClaim("at_hash").size() > 20)
    }

    @Feature("ID_TOKEN")
    def "Verify ID token mandatory elements when scope includes phone"() {
        expect:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap << [scope: "openid phone"]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", initLogin)
        Response token = Steps.followRedirectsToClientApplication(flow, taraAuthentication)
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, token.jsonPath().get("id_token")).JWTClaimsSet

        Set expectedClaims = [
                "acr", "amr", "at_hash", "aud", "auth_time",
                "birthdate", "exp", "family_name", "given_name", "iat",
                "iss", "jti", "nonce", "phone_number", "phone_number_verified",
                "rat", "sid", "sub"
        ]
        assertThat("JWT has only expected claims", claims.claims.keySet(), equalTo(expectedClaims))
        assertThat("Correct jti claim exists", claims.JWTID, matchesPattern("([a-f0-9]{8}(-[a-f0-9]{4}){4}[a-f0-9]{8})"))
        assertThat("Correct phone_number claim", claims.getClaim("phone_number"), equalTo("+37269100366"))
        assertThat("Correct phone_number_verified claim exists", claims.getClaim("phone_number_verified"), equalTo(true))
        assertThat("Correct nonce", claims.getClaim("nonce"), equalTo(flow.nonce))
        assertThat("Correct issuer", claims.issuer, equalTo(flow.openIdServiceConfiguration.get("issuer")))
        assertThat("Correct audience", claims.audience[0], equalTo(flow.oidcClientA.clientId))
        Date date = new Date()
        assertThat("Correct authentication time", Math.abs(date.time - claims.getDateClaim("auth_time").time) < 10000L)
        assertThat("Correct issued at time", Math.abs(date.time - claims.getDateClaim("iat").time) < 10000L)
        assertThat("Correct expiration time", claims.expirationTime.time - claims.getDateClaim("iat").time, equalTo(900000L))
        assertThat("Correct authentication method", claims.getClaim("amr"), equalTo(["mID"]))
        assertThat("Correct subject claim", claims.subject, equalTo("EE60001017716"))
        assertThat("Correct date of birth", claims.getClaim("birthdate"), equalTo("2000-01-01"))
        assertThat("Correct given name", claims.getClaim("given_name"), equalTo("ONE"))
        assertThat("Correct family name", claims.getClaim("family_name"), equalTo("TESTNUMBER"))
        assertThat("Correct LoA level", claims.getClaim("acr"), equalTo("high"))
        assertThat("Correct UUID pattern for session ID", claims.getStringClaim("sid"), matchesPattern("([a-f0-9]{8}(-[a-f0-9]{4}){4}[a-f0-9]{8})"))
        assertThat("Correct at_hash claim exists", claims.getStringClaim("at_hash").size() > 20)
    }

    @Feature("ID_TOKEN")
    def "Verify ID token elements after session update"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        JWTClaimsSet claims1 = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, createSession.jsonPath().get("id_token")).JWTClaimsSet

        // Sleep for one second to test that time claims in new ID token are unique from original ID token.
        sleep 1000
        Response updateSession = Steps.getSessionUpdateResponse(flow)

        JWTClaimsSet claims2 = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, updateSession.jsonPath().get("id_token")).JWTClaimsSet

        assertThat("New token", createSession.jsonPath().get("idToken"), not(updateSession.jsonPath().get("id_token")))
        assertThat("New at_hash", claims1.getClaim("at_hash"), not(claims2.getClaim("at_hash")))
        assertThat("New jti", claims1.getClaim("jti"), not(claims2.getClaim("jti")))
        assertThat("Correct nonce", claims1.getClaim("nonce"), is(claims2.getClaim("nonce")))
        assertThat("Correct LoA level", claims1.getClaim("acr"), is(claims2.getClaim("acr")))
        assertThat("Correct authentication method", claims1.getClaim("amr"), is(claims2.getClaim("amr")))
        assertThat("Correct authentication time", claims1.getClaim("auth_time"), is(claims2.getClaim("auth_time")))
        assertThat("Correct date of birth", claims1.getClaim("birthdate"), is(claims2.getClaim("birthdate")))
        assertThat("Correct family name", claims1.getClaim("family_name"), is(claims2.getClaim("family_name")))
        assertThat("Correct given name", claims1.getClaim("given_name"), is(claims2.getClaim("given_name")))
        assertThat("Correct issuer", claims1.issuer, is(claims2.issuer))
        assertThat("Correct session ID", claims1.getClaim("sid"), is(claims2.getClaim("sid")))
        assertThat("Correct audience", claims1.audience, is(claims2.audience))
        assertThat("Correct subject", claims1.subject, is(claims2.subject))
        assertThat("Updated expiration time", claims1.expirationTime < (claims2.expirationTime))
        assertThat("Updated issued at time", claims1.issueTime < (claims2.issueTime))
        assertThat("Correct token validity period", claims2.expirationTime.time - claims2.issueTime.time == 900000L)
    }

    @Feature("ID_TOKEN")
    def "Verify ID token elements after session update, scope includes phone"() {
        expect:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap << [scope: "openid phone"]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", initLogin)
        Steps.followRedirectsToClientApplication(flow, taraAuthentication)

        Response updateSession = Steps.getSessionUpdateResponse(flow)
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, updateSession.jsonPath().get("id_token")).JWTClaimsSet

        assertThat("Correct scope value", updateSession.jsonPath().getString("scope"), equalTo("openid phone"))
        assertThat("Correct phone_number claim", claims.getClaim("phone_number"), equalTo("+37269100366"))
        assertThat("Correct phone_number_verified claim", claims.getClaim("phone_number_verified"), equalTo(true))
    }

    @Feature("ID_TOKEN")
    def "Verify ID token elements after continuing session with client-B"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        JWTClaimsSet claimsClientA = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, createSession.body.jsonPath().get("id_token")).JWTClaimsSet

        //Sleep for one second to test that time claims in client-B ID token are unique from Client-A ID token.
        sleep 1000
        Response continueSession = Steps.continueWithExistingSession(flow)

        JWTClaimsSet claimsClientB = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, continueSession.body.jsonPath().get("id_token")).JWTClaimsSet

        assertThat("New token", createSession.jsonPath().get("idToken"), not(continueSession.jsonPath().get("id_token")))
        assertThat("New at_hash", claimsClientA.getClaim("at_hash"), not(claimsClientB.getClaim("at_hash")))
        assertThat("New jti", claimsClientA.getClaim("jti"), not(claimsClientB.getClaim("jti")))
        assertThat("New nonce", claimsClientA.getClaim("nonce"), not(claimsClientB.getClaim("nonce")))
        assertThat("Correct audience", claimsClientA.audience, not(claimsClientB.audience))
        assertThat("Correct LoA level", claimsClientA.getClaim("acr"), is(claimsClientB.getClaim("acr")))
        assertThat("Correct authentication method", claimsClientA.getClaim("amr"), is(claimsClientB.getClaim("amr")))
        assertThat("Correct authentication time", claimsClientA.getClaim("auth_time"), is(claimsClientB.getClaim("auth_time")))
        assertThat("Correct date of birth", claimsClientA.getClaim("birthdate"), is(claimsClientB.getClaim("birthdate")))
        assertThat("Correct family name", claimsClientA.getClaim("family_name"), is(claimsClientB.getClaim("family_name")))
        assertThat("Correct given name", claimsClientA.getClaim("given_name"), is(claimsClientB.getClaim("given_name")))
        assertThat("Correct issuer", claimsClientA.issuer, is(claimsClientB.issuer))
        assertThat("Correct session ID", claimsClientA.getClaim("sid"), is(claimsClientB.getClaim("sid")))
        assertThat("Correct subject", claimsClientA.subject, is(claimsClientB.subject))
        assertThat("Updated expiration time", claimsClientA.expirationTime < (claimsClientB.expirationTime))
        assertThat("Updated issued at time", claimsClientA.issueTime < (claimsClientB.issueTime))
        assertThat("Correct token validity period", claimsClientB.expirationTime.time - claimsClientB.issueTime.time == 900000L)
    }

    @Feature("ID_TOKEN")
    def "Verify ID token elements after continuing session with client-B. Client-A scope excludes phone, client-b scope includes phone"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)
        Response continueSession = Steps.continueWithExistingSessionWithScope(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl, "openid phone")
        JWTClaimsSet claimsClientB = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, continueSession.body.jsonPath().get("id_token")).JWTClaimsSet

        assertThat("Correct scope", continueSession.jsonPath().getString("scope"), is("openid phone"))
        assertThat("Claim phone_number does not exist", claimsClientB.claims, not(hasKey("phone_number")))
        assertThat("Claim phone_number_verified does not exist", claimsClientB.claims, not(hasKey("phone_number_verified")))
    }

    @Feature("ID_TOKEN")
    def "Verify ID token elements after continuing session with client-B. Client-A scope includes phone, client-b scope excludes phone"() {
        expect:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap << [scope: "openid phone"]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", initLogin)
        Steps.followRedirectsToClientApplication(flow, taraAuthentication)

        Response continueSession = Steps.continueWithExistingSessionWithScope(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl, "openid")
        JWTClaimsSet claimsClientB = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, continueSession.body.jsonPath().get("id_token")).JWTClaimsSet

        assertThat("Correct scope", continueSession.jsonPath().getString("scope"), is("openid"))
        assertThat("Claim phone_number does not exist", claimsClientB.claims, not(hasKey("phone_number")))
        assertThat("Claim phone_number_verified does not exist", claimsClientB.claims, not(hasKey("phone_number_verified")))
    }

    @Feature("ID_TOKEN")
    def "Verify ID token elements after continuing session with client-B. Client-A scope includes phone, client-b scope includes phone"() {
        expect:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap << [scope: "openid phone"]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", initLogin)
        Steps.followRedirectsToClientApplication(flow, taraAuthentication)

        Response continueSession = Steps.continueWithExistingSessionWithScope(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl, "openid phone")
        JWTClaimsSet claimsClientB = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, continueSession.body.jsonPath().get("id_token")).JWTClaimsSet

        assertThat("Correct scope", continueSession.jsonPath().getString("scope"), is("openid phone"))
        assertThat("Correct phone_number claim", claimsClientB.claims.get("phone_number"), is("+37269100366"))
        assertThat("Correct phone_number_verified claim", claimsClientB.claims.get("phone_number_verified"), is(true))
    }

    @Step("Follow redirects to client application")
    static Response followRedirectsToClientApplication(Flow flow, Response authenticationFinishedResponse) {
        Response initLogin = Steps.followRedirect(flow, authenticationFinishedResponse)
        Response loginVerifier = Steps.followRedirect(flow, initLogin)
        flow.setConsentChallenge(Utils.getParamValueFromResponseHeader(loginVerifier, "consent_challenge"))
        Response initConsent = Steps.followRedirect(flow, loginVerifier)
        return Steps.followRedirect(flow, initConsent)
    }
}
