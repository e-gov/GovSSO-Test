package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.hamcrest.Matchers.*
import static org.hamcrest.MatcherAssert.assertThat

class OidcIdentityTokenSpec extends GovSsoSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Feature("ID_TOKEN")
    def "Verify ID token response"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)

        assertThat("Correct token_type value", createSession.jsonPath().getString("token_type"), is("bearer"))
        assertThat("Correct scope value", createSession.jsonPath().getString("scope"), is("openid"))
        assertThat("Access token element exists", createSession.jsonPath().getString("access_token").size() > 32)
        assertThat("Expires in element exists", createSession.jsonPath().getInt("expires_in") <= 900)
        assertThat("ID token element exists", createSession.jsonPath().getString("id_token").size() > 1000)
        assertThat("Refresh token element exists", createSession.jsonPath().getString("refresh_token").size() == 87)
    }

    @Feature("ID_TOKEN")
    def "Verify ID token response when scope includes phone"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.put("scope", "openid phone")
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", initLogin)
        Response consentVerifier = Steps.followRedirectsToClientApplication(flow, taraAuthentication)

        Response token = Steps.getIdentityTokenResponseWithDefaults(flow, consentVerifier)

        assertThat("Correct token_type value", token.jsonPath().getString("token_type"), is("bearer"))
        assertThat("Correct scope value", token.jsonPath().getString("scope"), is("openid phone"))
        assertThat("Access token element exists", token.jsonPath().getString("access_token").size() > 32)
        assertThat("Expires in element exists", token.jsonPath().getInt("expires_in") <= 900)
        assertThat("ID token element exists", token.jsonPath().getString("id_token").size() > 1000)
    }

    @Feature("ID_TOKEN")
    def "Verify ID token mandatory elements"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, createSession.jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat("Correct JWT ID claim exists", claims.getJWTID().size() > 35)
        assertThat("Correct nonce", claims.getClaim("nonce"), equalTo(flow.nonce))
        assertThat("Correct issuer", claims.getIssuer(), equalTo(flow.openIdServiceConfiguration.get("issuer")))
        assertThat("Correct audience", claims.getAudience().get(0), equalTo(flow.oidcClientA.clientId))
        Date date = new Date()
        assertThat("Correct authentication time", Math.abs(date.getTime() - claims.getDateClaim("auth_time").getTime()) < 10000L)
        assertThat("Correct issued at time", Math.abs(date.getTime() - claims.getDateClaim("iat").getTime()) < 10000L)
        assertThat("Correct expiration time", claims.getDateClaim("exp").getTime() - claims.getDateClaim("iat").getTime(), equalTo(900000L))
        assertThat("Correct authentication method", claims.getClaim("amr"), equalTo(["idcard"]))
        assertThat("Correct subject claim", claims.getSubject(), equalTo("EE38001085718"))
        assertThat("Correct date of birth", claims.getClaim("birthdate"),  equalTo("1980-01-08"))
        assertThat("Correct given name", claims.getClaim("given_name"),  equalTo("JAAK-KRISTJAN"))
        assertThat("Correct family name", claims.getClaim("family_name"),  equalTo("JÕEORG"))
        assertThat("Correct LoA level", claims.getClaim("acr"), equalTo("high"))
        assertThat("Correct UUID pattern for session ID", claims.getStringClaim("sid"), matchesPattern("([a-f0-9]{8}(-[a-f0-9]{4}){4}[a-f0-9]{8})"))
        assertThat("Claim phone_number does not exist", claims.getClaims(), not(hasKey("phone_number")))
        assertThat("Claim phone_number_verified does not exist", claims.getClaims(), not(hasKey("phone_number_verified")))
        assertThat("Correct at_hash claim exists", claims.getStringClaim("at_hash").size()  > 20)
    }

    @Feature("ID_TOKEN")
    def "Verify ID token mandatory elements when scope includes phone"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.put("scope", "openid phone")
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", initLogin)
        Response consentVerifier = Steps.followRedirectsToClientApplication(flow, taraAuthentication)
        Response token = Steps.getIdentityTokenResponseWithDefaults(flow, consentVerifier)
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, token.jsonPath().get("id_token")).getJWTClaimsSet()

        assertThat("Correct jti claim exists", claims.getJWTID().size() > 35)
        assertThat("Correct phone_number claim", claims.getClaim("phone_number"), equalTo("+37269100366"))
        assertThat("Correct phone_number_verified claim exists", claims.getClaim("phone_number_verified"), equalTo(true))
        assertThat("Correct nonce", claims.getClaim("nonce"), equalTo(flow.nonce))
        assertThat("Correct issuer", claims.getIssuer(), equalTo(flow.openIdServiceConfiguration.get("issuer")))
        assertThat("Correct audience", claims.getAudience().get(0), equalTo(flow.oidcClientA.clientId))
        Date date = new Date()
        assertThat("Correct authentication time", Math.abs(date.getTime() - claims.getDateClaim("auth_time").getTime()) < 10000L)
        assertThat("Correct issued at time", Math.abs(date.getTime() - claims.getDateClaim("iat").getTime()) < 10000L)
        assertThat("Correct expiration time", claims.getDateClaim("exp").getTime() - claims.getDateClaim("iat").getTime(), equalTo(900000L))
        assertThat("Correct authentication method", claims.getClaim("amr"), equalTo(["mID"]))
        assertThat("Correct subject claim", claims.getSubject(), equalTo("EE60001017716"))
        assertThat("Correct date of birth", claims.getClaim("birthdate"),  equalTo("2000-01-01"))
        assertThat("Correct given name", claims.getClaim("given_name"),  equalTo("ONE"))
        assertThat("Correct family name", claims.getClaim("family_name"),  equalTo("TESTNUMBER"))
        assertThat("Correct LoA level", claims.getClaim("acr"), equalTo("high"))
        assertThat("Correct UUID pattern for session ID", claims.getStringClaim("sid"), matchesPattern("([a-f0-9]{8}(-[a-f0-9]{4}){4}[a-f0-9]{8})"))
        assertThat("Correct at_hash claim exists", claims.getStringClaim("at_hash").size()  > 20)
    }

    @Feature("ID_TOKEN")
    def "Verify ID token elements after session update"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        String refreshToken = createSession.jsonPath().get("refresh_token")
        JWTClaimsSet claims1 = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, createSession.jsonPath().get("id_token")).getJWTClaimsSet()
        Thread.sleep(1000)
        Response updateSession = Steps.getSessionUpdateResponse(flow, refreshToken, flow.oidcClientA.clientId, flow.oidcClientA.clientSecret, flow.oidcClientA.fullBaseUrl)

        JWTClaimsSet claims2 = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, updateSession.jsonPath().get("id_token")).getJWTClaimsSet()

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
        assertThat("Correct issuer", claims1.getClaim("issuer"), is(claims2.getClaim("issuer")))
        assertThat("Correct session ID", claims1.getClaim("sid"), is(claims2.getClaim("sid")))
        assertThat("Correct audience", claims1.getClaim("aud"), is(claims2.getClaim("aud")))
        assertThat("Correct subject", claims1.getSubject(), is(claims2.getSubject()))
        assertThat("Updated expiration time", claims1.getExpirationTime() < (claims2.getExpirationTime()))
        assertThat("Updated issued at time", claims1.getIssueTime() < (claims2.getIssueTime()))
        assertThat("Correct token validity period", claims2.getExpirationTime().getTime() - claims2.getIssueTime().getTime() == 900000L)
    }

    @Feature("ID_TOKEN")
    def "Verify ID token elements after session update, scope includes phone"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.put("scope", "openid phone")
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", initLogin)
        Response consentVerifier = Steps.followRedirectsToClientApplication(flow, taraAuthentication)
        Response token = Steps.getIdentityTokenResponseWithDefaults(flow, consentVerifier)

        String refreshToken = token.jsonPath().get("refresh_token")

        Response updateSession = Steps.getSessionUpdateResponse(flow, refreshToken, flow.oidcClientA.clientId, flow.oidcClientA.clientSecret, flow.oidcClientA.fullBaseUrl)
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, updateSession.jsonPath().get("id_token")).getJWTClaimsSet()

        assertThat("Correct scope value", updateSession.jsonPath().getString("scope"), equalTo("openid phone"))
        assertThat("Correct phone_number claim", claims.getClaim("phone_number"), equalTo("+37269100366"))
        assertThat("Correct phone_number_verified claim", claims.getClaim("phone_number_verified"), equalTo(true))
    }

    @Feature("ID_TOKEN")
    def "Verify ID token elements after continuing session with client-B"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        JWTClaimsSet claimsClientA = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, createSession.getBody().jsonPath().get("id_token")).getJWTClaimsSet()

        Response continueSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)

        JWTClaimsSet claimsClientB = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, continueSession.getBody().jsonPath().get("id_token"), flow.oidcClientB.clientId).getJWTClaimsSet()

        assertThat("New token", createSession.jsonPath().get("idToken"), not(continueSession.jsonPath().get("id_token")))
        assertThat("New at_hash", claimsClientA.getClaim("at_hash"), not(claimsClientB.getClaim("at_hash")))
        assertThat("New jti", claimsClientA.getClaim("jti"), not(claimsClientB.getClaim("jti")))
        assertThat("New nonce", claimsClientA.getClaim("nonce"), not(claimsClientB.getClaim("nonce")))
        assertThat("Correct audience", claimsClientA.getClaim("aud"), not(claimsClientB.getClaim("aud")))
        assertThat("Correct LoA level", claimsClientA.getClaim("acr"), is(claimsClientB.getClaim("acr")))
        assertThat("Correct authentication method", claimsClientA.getClaim("amr"), is(claimsClientB.getClaim("amr")))
        assertThat("Correct authentication time", claimsClientA.getClaim("auth_time"), is(claimsClientB.getClaim("auth_time")))
        assertThat("Correct date of birth", claimsClientA.getClaim("birthdate"), is(claimsClientB.getClaim("birthdate")))
        assertThat("Correct family name", claimsClientA.getClaim("family_name"), is(claimsClientB.getClaim("family_name")))
        assertThat("Correct given name", claimsClientA.getClaim("given_name"), is(claimsClientB.getClaim("given_name")))
        assertThat("Correct issuer", claimsClientA.getClaim("issuer"), is(claimsClientB.getClaim("issuer")))
        assertThat("Correct session ID", claimsClientA.getClaim("sid"), is(claimsClientB.getClaim("sid")))
        assertThat("Correct subject", claimsClientA.getSubject(), is(claimsClientB.getSubject()))
        assertThat("Updated expiration time", claimsClientA.getExpirationTime() < (claimsClientB.getExpirationTime()))
        assertThat("Updated issued at time", claimsClientA.getIssueTime() < (claimsClientB.getIssueTime()))
        assertThat("Correct token validity period", claimsClientB.getExpirationTime().getTime() - claimsClientB.getIssueTime().getTime() == 900000L)
    }

    @Feature("ID_TOKEN")
    def "Verify ID token elements after continuing session with client-B. Client-A scope excludes phone, client-b scope includes phone"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)
        Response continueSession = Steps.continueWithExistingSessionWithScope(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl, "openid phone")
        JWTClaimsSet claimsClientB = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, continueSession.getBody().jsonPath().get("id_token"), flow.oidcClientB.clientId).getJWTClaimsSet()

        assertThat("Correct scope", continueSession.jsonPath().getString("scope"), is("openid phone"))
        assertThat("Claim phone_number does not exist", claimsClientB.getClaims(), not(hasKey("phone_number")))
        assertThat("Claim phone_number_verified does not exist", claimsClientB.getClaims(), not(hasKey("phone_number_verified")))
    }

    @Feature("ID_TOKEN")
    def "Verify ID token elements after continuing session with client-B. Client-A scope includes phone, client-b scope excludes phone"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.put("scope", "openid phone")
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", initLogin)
        Response consentVerifier = Steps.followRedirectsToClientApplication(flow, taraAuthentication)
        Steps.getIdentityTokenResponseWithDefaults(flow, consentVerifier)

        Response continueSession = Steps.continueWithExistingSessionWithScope(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl, "openid")
        JWTClaimsSet claimsClientB = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, continueSession.getBody().jsonPath().get("id_token"), flow.oidcClientB.clientId).getJWTClaimsSet()

        assertThat("Correct scope", continueSession.jsonPath().getString("scope"), is("openid"))
        assertThat("Claim phone_number does not exist", claimsClientB.getClaims(), not(hasKey("phone_number")))
        assertThat("Claim phone_number_verified does not exist", claimsClientB.getClaims(), not(hasKey("phone_number_verified")))
    }

    @Feature("ID_TOKEN")
    def "Verify ID token elements after continuing session with client-B. Client-A scope includes phone, client-b scope includes phone"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.put("scope", "openid phone")
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", initLogin)
        Response consentVerifier = Steps.followRedirectsToClientApplication(flow, taraAuthentication)
        Steps.getIdentityTokenResponseWithDefaults(flow, consentVerifier)

        Response continueSession = Steps.continueWithExistingSessionWithScope(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl, "openid phone")
        JWTClaimsSet claimsClientB = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, continueSession.getBody().jsonPath().get("id_token"), flow.oidcClientB.clientId).getJWTClaimsSet()

        assertThat("Correct scope", continueSession.jsonPath().getString("scope"), is("openid phone"))
        assertThat("Correct phone_number claim", claimsClientB.getClaims().get("phone_number"), is("+37269100366"))
        assertThat("Correct phone_number_verified claim", claimsClientB.getClaims().get("phone_number_verified"), is(true))
    }
}
