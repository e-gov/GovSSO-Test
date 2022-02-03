package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Ignore

import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.matchesPattern
import static org.junit.jupiter.api.Assertions.*
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
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)
        Response authenticationFinishedResponse = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", sessionServiceRedirectToTaraResponse)
        Response oidcServiceConsentResponse = Steps.followRedirectsToClientApplication(flow, authenticationFinishedResponse)

        Response tokenResponse = Steps.getIdentityTokenResponseWithDefaults(flow, oidcServiceConsentResponse)

        assertEquals("bearer", tokenResponse.body().jsonPath().getString("token_type"), "Correct token_type value")
        assertEquals("openid", tokenResponse.body().jsonPath().getString("scope"), "Correct scope value")
        assertTrue(tokenResponse.body().jsonPath().getString("access_token").size() > 32, "Access token element exists")
        assertTrue(tokenResponse.body().jsonPath().getInt("expires_in") <= 1, "Expires in element exists")
        assertTrue(tokenResponse.body().jsonPath().getString("id_token").size() > 1000, "ID token element exists")
    }

    @Feature("ID_TOKEN")
    def "Verify ID token mandatory elements"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)
        Response authenticationFinishedResponse = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", sessionServiceRedirectToTaraResponse)
        Response oidcServiceConsentResponse = Steps.followRedirectsToClientApplication(flow, authenticationFinishedResponse)

        Response tokenResponse = Steps.getIdentityTokenResponseWithDefaults(flow, oidcServiceConsentResponse)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertTrue(claims.getJWTID().size() > 35, "Correct jti claim exists")
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
        assertThat("Correct UUID pattern for session ID", claims.getClaim("sid"), matchesPattern("([a-f0-9]{8}(-[a-f0-9]{4}){4}[a-f0-9]{8})"))
        assertTrue(claims.getStringClaim("at_hash").size()  > 20, "Correct at_hash claim exists")
    }

    @Ignore
    @Feature("ID_TOKEN")
    def "Verify ID token with optional elements by phone scope"() {
        expect:
        String scopeList = "openid phone"
        TaraSteps.startAuthenticationInTara(flow, scopeList)
        String idCode = "60001017716"
        String phoneNo = "69100366"
        Response midAuthResponse = TaraSteps.authenticateWithMid(flow, idCode, phoneNo)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirectsSso(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponseWithDefaults(flow, authenticationFinishedResponse)
        assertEquals("bearer", tokenResponse.body().jsonPath().getString("token_type"), "Correct token_type value")
        assertEquals(scopeList, tokenResponse.body().jsonPath().getString("scope"), "Correct scope value")
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat("Correct subject claim", claims.getSubject(), equalTo("EE" + idCode))
        assertThat("Phone_number claim exists", claims.getStringClaim("phone_number"), equalTo("+372" + phoneNo))
        assertThat("Phone_number_verified claim exists", claims.getBooleanClaim("phone_number_verified"), equalTo(true))
    }

    @Ignore
    @Feature("ID_TOKEN")
    def "Verify ID token with optional elements by email scope"() {
        expect:
        String scopeList = "openid email"
        TaraSteps.startAuthenticationInTara(flow, scopeList)
        Response idCardAuthResponse = TaraSteps.authenticateWithIdCard(flow, "src/test/resources/joeorg-auth.pem")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirectsSso(flow, true, idCardAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponseWithDefaults(flow, authenticationFinishedResponse)
        assertEquals("bearer", tokenResponse.body().jsonPath().getString("token_type"), "Correct token_type value")
        assertEquals(scopeList, tokenResponse.body().jsonPath().getString("scope"), "Correct scope value")
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat("Correct subject claim", claims.getSubject(), equalTo("EE38001085718"))
        assertThat("Phone_number claim exists", claims.getStringClaim("email"), equalTo("38001085718@eesti.ee"))
        assertThat("Phone_number_verified claim exists", claims.getBooleanClaim("email_verified"), equalTo(false))
    }
}
