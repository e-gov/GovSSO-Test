package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.hamcrest.Matchers
import spock.lang.Ignore

import static org.hamcrest.Matchers.equalTo
import static org.junit.jupiter.api.Assertions.*
import static org.hamcrest.MatcherAssert.assertThat

//TODO: Transferred tests from TARA2 project for preliminary usage

class OidcIdendityTokenSpec extends GovSsoSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Ignore
    @Feature("")
    def "Verify ID token response"() {
        expect:
        //Steps.startAuthenticationInTara(flow)
        Response midAuthResponse = TaraSteps.authenticateWithMid(flow,"60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirectsSso(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        assertEquals("bearer", tokenResponse.body().jsonPath().getString("token_type"), "Correct token_type value")
        assertEquals("openid", tokenResponse.body().jsonPath().getString("scope"), "Correct scope value")
        assertTrue(tokenResponse.body().jsonPath().getString("access_token").size() > 32, "Access token element exists")
        assertTrue(tokenResponse.body().jsonPath().getInt("expires_in") > 60, "Expires in element exists")
        assertTrue(tokenResponse.body().jsonPath().getString("id_token").size() > 1000, "ID token element exists")
    }

    @Ignore
    @Feature("")
    def "Verify ID token mandatory elements"() {
        expect:
        //Steps.startAuthenticationInTara(flow)
        String idCode = "60001017716"
        String phoneNo = "69100366"
        Response midAuthResponse = TaraSteps.authenticateWithMid(flow, idCode, phoneNo)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirectsSso(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        assertEquals("bearer", tokenResponse.body().jsonPath().getString("token_type"), "Correct token_type value")
        assertEquals("openid", tokenResponse.body().jsonPath().getString("scope"), "Correct scope value")
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertTrue(claims.getJWTID().size() > 35, "Correct jti claim exists")
        assertThat("Correct issuer claim", claims.getIssuer(), equalTo(flow.openIdServiceConfiguration.get("issuer")))
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClient.clientId))
        Date date = new Date()
        assertThat("Expected current: " + date + " to be after nbf: " + claims.getNotBeforeTime(), date.after(claims.getNotBeforeTime()), Matchers.is(true))
        // 10 seconds
        assertTrue(Math.abs(date.getTime() - claims.getDateClaim("iat").getTime()) < 10000L, "Correct iat claim")
        assertThat("Correct subject claim", claims.getSubject(), equalTo("EE" + idCode))

        assertThat("Correct date of birth", claims.getJSONObjectClaim("profile_attributes").get("date_of_birth"),  equalTo("2000-01-01"))
        assertThat("Correct given name", claims.getJSONObjectClaim("profile_attributes").get("given_name"),  equalTo("ONE"))
        assertThat("Correct family name", claims.getJSONObjectClaim("profile_attributes").get("family_name"),  equalTo("TESTNUMBER"))
        assertThat("Correct amr value", claims.getStringArrayClaim("amr")[0].toString(), Matchers.oneOf("smartid", "eIDAS", "idcard", "mID"))

        assertThat("Correct state value", claims.getStringClaim("state"), equalTo(flow.getState()))
        assertThat("Correct LoA level", claims.getStringClaim("acr"), equalTo("high"))
        assertTrue(claims.getStringClaim("at_hash").size()  > 20, "Correct at_hash claim exists")
    }

    @Ignore
    @Feature("")
    def "Verify ID token with optional elements by phone scope"() {
        expect:
        String scopeList = "openid phone"
 //       Steps.startAuthenticationInTara(flow, scopeList)
        String idCode = "60001017716"
        String phoneNo = "69100366"
        Response midAuthResponse = TaraSteps.authenticateWithMid(flow, idCode, phoneNo)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirectsSso(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        assertEquals("bearer", tokenResponse.body().jsonPath().getString("token_type"), "Correct token_type value")
        assertEquals(scopeList, tokenResponse.body().jsonPath().getString("scope"), "Correct scope value")
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat("Correct subject claim", claims.getSubject(), equalTo("EE" + idCode))
        assertThat("Phone_number claim exists", claims.getStringClaim("phone_number"), equalTo("+372" + phoneNo))
        assertThat("Phone_number_verified claim exists", claims.getBooleanClaim("phone_number_verified"), equalTo(true))
    }

    @Ignore
    @Feature("")
    def "Verify ID token with optional elements by email scope"() {
        expect:
        String scopeList = "openid email"
        TaraSteps.startAuthenticationInTara(flow, scopeList)
        Response idCardAuthResponse = TaraSteps.authenticateWithIdCard(flow, "src/test/resources/joeorg-auth.pem")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirectsSso(flow, true, idCardAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        assertEquals("bearer", tokenResponse.body().jsonPath().getString("token_type"), "Correct token_type value")
        assertEquals(scopeList, tokenResponse.body().jsonPath().getString("scope"), "Correct scope value")
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat("Correct subject claim", claims.getSubject(), equalTo("EE38001085718"))
        assertThat("Phone_number claim exists", claims.getStringClaim("email"), equalTo("38001085718@eesti.ee"))
        assertThat("Phone_number_verified claim exists", claims.getBooleanClaim("email_verified"), equalTo(false))
    }
}
