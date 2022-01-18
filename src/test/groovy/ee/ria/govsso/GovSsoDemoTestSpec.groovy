package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.MatcherAssert.assertThat
import static org.junit.jupiter.api.Assertions.assertEquals

class GovSsoDemoTestSpec extends GovSsoSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Feature("AUTHENTICATION")
    def "Authentication with Mobile-ID"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)

        Response authenticationFinishedResponse = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", sessionServiceRedirectToTaraResponse)

        Response oidcServiceConsentResponse = Steps.followRedirectsToClientApplication(flow, authenticationFinishedResponse)

        Response tokenResponse = Steps.getIdentityTokenResponseWithDefaults(flow, oidcServiceConsentResponse)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientA.clientId))
        assertThat(claims.getSubject(), equalTo("EE60001017716"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("Eesnimi"))
    }

    @Feature("AUTHENTICATION")
    def "Authenticate with Smart-ID"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)

        Response authenticationFinishedResponse = TaraSteps.authenticateWithSidInTARA(flow, "30303039914", sessionServiceRedirectToTaraResponse)

        Response oidcServiceConsentResponse = Steps.followRedirectsToClientApplication(flow, authenticationFinishedResponse)

        Response tokenResponse = Steps.getIdentityTokenResponseWithDefaults(flow, oidcServiceConsentResponse)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientA.clientId))
        assertThat(claims.getSubject(), equalTo("EE30303039914"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("Eesnimi"))    }

    @Feature("AUTHENTICATION")
    def "Authenticate with ID-Card"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)

        Response authenticationFinishedResponse = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)

        Response oidcServiceConsentResponse = Steps.followRedirectsToClientApplication(flow, authenticationFinishedResponse)

        Response tokenResponse = Steps.getIdentityTokenResponseWithDefaults(flow, oidcServiceConsentResponse)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientA.clientId))
        assertThat(claims.getSubject(), equalTo("EE38001085718"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("Eesnimi"))
    }

    @Feature("AUTHENTICATION")
    def "Authenticate with Eidas"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)

        Response authenticationFinishedResponse = TaraSteps.authenticateWithEidasInTARA(flow, "CA", IDP_USERNAME, IDP_PASSWORD, EIDASLOA, sessionServiceRedirectToTaraResponse)

        Response oidcServiceConsentResponse = Steps.followRedirectsToClientApplication(flow, authenticationFinishedResponse)

        Response tokenResponse = Steps.getIdentityTokenResponseWithDefaults(flow, oidcServiceConsentResponse)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientA.clientId))
        assertThat(claims.getSubject(), equalTo("CA12345"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("Eesnimi"))
       }

    @Feature("AUTHENTICATION")
    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Authentication with Mobile-ID in client-A and continue session in client-B"() {
        expect:
        Response createSession = Steps.authenticateWithMidInGovsso(flow)
        JWTClaimsSet claimsClientA = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, createSession.getBody().jsonPath().get("id_token")).getJWTClaimsSet()

        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcServiceInitResponse)
        Response continueWithExistingSession = Requests.postRequestWithCookies(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies)
        Response followRedirects = Steps.followRedirectsToClientApplicationWithExistingSession(flow, continueWithExistingSession, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        JWTClaimsSet claimsClientB = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, followRedirects.getBody().jsonPath().get("id_token"), flow.oidcClientB.clientId).getJWTClaimsSet()

        assertEquals(flow.oidcClientB.clientId, claimsClientB.getAudience().get(0), "Correct aud value")
        assertEquals("EE60001017716", claimsClientB.getSubject(), "Correct subject value")
        assertEquals(claimsClientA.getClaim("sid"), claimsClientB.getClaim("sid"), "Correct session ID")
    }
}
