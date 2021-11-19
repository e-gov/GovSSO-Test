package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Ignore

import static org.hamcrest.Matchers.emptyOrNullString
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.not
import static org.junit.jupiter.api.Assertions.*
import static org.hamcrest.MatcherAssert.assertThat

class GovSsoDemoTestSpec extends GovSsoSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Ignore
    @Feature("AUTHENTICATION")
    def "authentication with Mobile-ID"() {
        expect:
        //TODO: Start authentication in GOVSSO until redirect to TARA
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)

        //Authenticate in TARA with Mid
        Response authenticationFinishedResponse = Steps.authenticateWithMidInTARA(flow, "60001017716", "69100366", sessionServiceRedirectToTaraResponse)

        //TODO: Follow redirects in GOVSSO and assert
        Response sessionServiceResponse = Steps.followRedirectWithCookies(flow, authenticationFinishedResponse, flow.ssoOidcService.cookies)
        Response oidcServiceResponse = Steps.followRedirectWithCookies(flow, sessionServiceResponse, flow.ssoOidcService.cookies)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_consent_csrf_insecure", oidcServiceResponse.getCookie("oauth2_consent_csrf_insecure"))
        Response sessionServiceConsentResponse = Steps.followRedirectWithCookies(flow, oidcServiceResponse, flow.ssoOidcService.cookies)
        Response oidcServiceConsentResponse = Steps.followRedirectWithCookies(flow, sessionServiceConsentResponse, flow.ssoOidcService.cookies)

        Response tokenResponse = Steps.getIdentityTokenResponse(flow, oidcServiceConsentResponse)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientA.clientId))
        assertThat(claims.getSubject(), equalTo("EE60001017716"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("Eesnimi"))
    }

    @Ignore
    @Feature("AUTHENTICATION")
    def "authenticate with Smart-ID"() {
        expect:
        //TODO: Start authentication in GOVSSO until redirect to TARA
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)

        //Authenticate in TARA with Sid
        Response authenticationFinishedResponse = Steps.authenticateWithSidInTARA(flow, "30303039914", sessionServiceRedirectToTaraResponse)

        //TODO: Follow redirects in GOVSSO and assert
        Response sessionServiceResponse = Steps.followRedirectWithCookies(flow, authenticationFinishedResponse, flow.ssoOidcService.cookies)
        Response oidcServiceResponse = Steps.followRedirectWithCookies(flow, sessionServiceResponse, flow.ssoOidcService.cookies)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_consent_csrf_insecure", oidcServiceResponse.getCookie("oauth2_consent_csrf_insecure"))
        Response sessionServiceConsentResponse = Steps.followRedirectWithCookies(flow, oidcServiceResponse, flow.ssoOidcService.cookies)
        Response oidcServiceConsentResponse = Steps.followRedirectWithCookies(flow, sessionServiceConsentResponse, flow.ssoOidcService.cookies)

        Response tokenResponse = Steps.getIdentityTokenResponse(flow, oidcServiceConsentResponse)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientA.clientId))
        assertThat(claims.getSubject(), equalTo("EE30303039914"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("Eesnimi"))    }

    @Feature("AUTHENTICATION")
    def "authenticate with Eidas"() {
        expect:
        //TODO: Start authentication in GOVSSO until redirect to TARA
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)

        //Authenticate in TARA with eIDAS
        Response authenticationFinishedResponse = Steps.authenticateWithEidasInTARA(flow, "CA", IDP_USERNAME, IDP_PASSWORD, EIDASLOA, sessionServiceRedirectToTaraResponse)

        //TODO: Follow redirects in GOVSSO and assert
        Response sessionServiceResponse = Steps.followRedirectWithCookies(flow, authenticationFinishedResponse, flow.ssoOidcService.cookies)
        Response oidcServiceResponse = Steps.followRedirectWithCookies(flow, sessionServiceResponse, flow.ssoOidcService.cookies)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_consent_csrf_insecure", oidcServiceResponse.getCookie("oauth2_consent_csrf_insecure"))
        Response sessionServiceConsentResponse = Steps.followRedirectWithCookies(flow, oidcServiceResponse, flow.ssoOidcService.cookies)
        Response oidcServiceConsentResponse = Steps.followRedirectWithCookies(flow, sessionServiceConsentResponse, flow.ssoOidcService.cookies)

        Response tokenResponse = Steps.getIdentityTokenResponse(flow, oidcServiceConsentResponse)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientA.clientId))
        assertThat(claims.getSubject(), equalTo("CA12345"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("Eesnimi"))
       }

    @Ignore
    @Feature("AUTHENTICATION")
    def "authenticate with ID-Card"() {
        expect:
        //TODO: Start authentication in GOVSSO until redirect to TARA

        //Authenticate in TARA with ID-Card
        Response authenticationFinishedResponse = Steps.authenticateWithIdCardInTARA(flow)

        //TODO: Follow redirects in GOVSSO and assert
        assertEquals(302, authenticationFinishedResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat("Authorization code should be returned", Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "code"), not(emptyOrNullString()))
    }
}
