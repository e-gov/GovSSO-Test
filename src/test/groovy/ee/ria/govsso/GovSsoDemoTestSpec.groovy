package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.MatcherAssert.assertThat

class GovSsoDemoTestSpec extends GovSsoSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Feature("AUTHENTICATION")
    def "authentication with Mobile-ID"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)

        Response authenticationFinishedResponse = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", sessionServiceRedirectToTaraResponse)

        Response oidcServiceConsentResponse = Steps.followRedirectsToClientApplication(flow, authenticationFinishedResponse)

        Response tokenResponse = Steps.getIdentityTokenResponse(flow, oidcServiceConsentResponse)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientA.clientId))
        assertThat(claims.getSubject(), equalTo("EE60001017716"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("Eesnimi"))
    }

    @Feature("AUTHENTICATION")
    def "authenticate with Smart-ID"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)

        Response authenticationFinishedResponse = TaraSteps.authenticateWithSidInTARA(flow, "30303039914", sessionServiceRedirectToTaraResponse)

        Response oidcServiceConsentResponse = Steps.followRedirectsToClientApplication(flow, authenticationFinishedResponse)

        Response tokenResponse = Steps.getIdentityTokenResponse(flow, oidcServiceConsentResponse)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientA.clientId))
        assertThat(claims.getSubject(), equalTo("EE30303039914"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("Eesnimi"))    }

    @Feature("AUTHENTICATION")
    def "authenticate with ID-Card"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)

        Response authenticationFinishedResponse = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)

        Response oidcServiceConsentResponse = Steps.followRedirectsToClientApplication(flow, authenticationFinishedResponse)

        Response tokenResponse = Steps.getIdentityTokenResponse(flow, oidcServiceConsentResponse)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientA.clientId))
        assertThat(claims.getSubject(), equalTo("EE38001085718"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("Eesnimi"))
    }

    @Feature("AUTHENTICATION")
    def "authenticate with Eidas"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)

        Response authenticationFinishedResponse = TaraSteps.authenticateWithEidasInTARA(flow, "CA", IDP_USERNAME, IDP_PASSWORD, EIDASLOA, sessionServiceRedirectToTaraResponse)

        Response oidcServiceConsentResponse = Steps.followRedirectsToClientApplication(flow, authenticationFinishedResponse)

        Response tokenResponse = Steps.getIdentityTokenResponse(flow, oidcServiceConsentResponse)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientA.clientId))
        assertThat(claims.getSubject(), equalTo("CA12345"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("Eesnimi"))
       }
}
