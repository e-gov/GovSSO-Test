package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

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
        Response createSession = Steps.authenticateWithIdCardInGovsso(flow)

        assertEquals("bearer", createSession.body().jsonPath().getString("token_type"), "Correct token_type value")
        assertEquals("openid", createSession.body().jsonPath().getString("scope"), "Correct scope value")
        assertTrue(createSession.body().jsonPath().getString("access_token").size() > 32, "Access token element exists")
        assertTrue(createSession.body().jsonPath().getInt("expires_in") <= 1, "Expires in element exists")
        assertTrue(createSession.body().jsonPath().getString("id_token").size() > 1000, "ID token element exists")
    }

    @Feature("ID_TOKEN")
    def "Verify ID token mandatory elements"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovsso(flow)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, createSession.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertTrue(claims.getJWTID().size() > 35, "Correct jti claim exists")
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
        assertTrue(claims.getStringClaim("at_hash").size()  > 20, "Correct at_hash claim exists")
    }

    @Feature("ID_TOKEN")
    def "Verify ID token elements after session refresh"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovsso(flow)
        String idToken = createSession.jsonPath().get("id_token")
        JWTClaimsSet claims1 = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, createSession.getBody().jsonPath().get("id_token")).getJWTClaimsSet()

        Response refreshSession = Steps.refreshSessionWithDefaults(flow, idToken)
        Response tokenResponse2 = Steps.getIdentityTokenResponseWithDefaults(flow, refreshSession)

        JWTClaimsSet claims2 = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, tokenResponse2.getBody().jsonPath().get("id_token")).getJWTClaimsSet()

        assertNotEquals(idToken, tokenResponse2.jsonPath().get("id_token"), "New token")
        assertNotEquals(claims1.getClaim("at_hash"), claims2.getClaim("at_hash"), "New at_hash")
        assertNotEquals(claims1.getClaim("jti"), claims2.getClaim("jti"), "New jti")
        assertNotEquals(claims1.getClaim("nonce"), claims2.getClaim("nonce"), "New nonce")
        assertEquals(claims1.getClaim("acr"), claims2.getClaim("acr"), "Correct acr")
        assertEquals(claims1.getClaim("amr"), claims2.getClaim("amr"), "Correct amr")
        assertEquals(claims1.getClaim("auth_time"), claims2.getClaim("auth_time"), "Correct auth_time")
        assertEquals(claims1.getClaim("birthdate"), claims2.getClaim("birthdate"), "Correct birthdate")
        assertEquals(claims1.getAudience().get(0), claims2.getAudience().get(0), "Correct audience")
        assertEquals(claims1.getClaim("family_name"), claims2.getClaim("family_name"), "Correct family_name")
        assertEquals(claims1.getClaim("given_name"), claims2.getClaim("given_name"), "Correct given_name")
        assertEquals(claims1.getClaim("iss"), claims2.getClaim("iss"), "Correct issuer")
        assertEquals(claims1.getClaim("sid"), claims2.getClaim("sid"), "Correct sid")
        assertEquals(claims1.getSubject(), claims2.getSubject(), "Correct subject")
        assertTrue(claims1.getExpirationTime() <= claims2.getExpirationTime(), "Updated exp")
        assertTrue(claims1.getIssueTime() < claims2.getIssueTime(), "Updated iat")
        assertTrue(claims2.getExpirationTime().getTime() - claims2.getIssueTime().getTime() == 900000L, "Correct token validity period")
    }
}
