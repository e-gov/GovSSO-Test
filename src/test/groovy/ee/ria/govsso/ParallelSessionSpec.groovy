package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Ignore

import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.not
import static org.hamcrest.Matchers.startsWith
import static org.hamcrest.MatcherAssert.assertThat

class ParallelSessionSpec extends GovSsoSpecification {

    Flow flow1 = new Flow(props)
    Flow flow2 = new Flow(props)


    def setup() {
        flow1.cookieFilter = new CookieFilter()
        flow2.cookieFilter = new CookieFilter()
        flow1.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow1.ssoOidcService.fullConfigurationUrl)
        flow2.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow2.ssoOidcService.fullConfigurationUrl)
        flow1.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow1.ssoOidcService.fullJwksUrl))
        flow2.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow2.ssoOidcService.fullJwksUrl))
    }

    @Feature("PARALLEL_SESSIONS")
    def "Same user's separate concurrent sessions have separate session ID-s"() {
        expect:
        Response session1 = Steps.authenticateWithIdCardInGovSso(flow1)
        String idToken1 = session1.path("id_token")
        String refreshToken1 = session1.path("refresh_token")
        JWTClaimsSet claims1 = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow1, idToken1).JWTClaimsSet

        Response session2 = Steps.authenticateWithIdCardInGovSso(flow2)
        String idToken2 = session2.path("id_token")
        String refreshToken2 = session2.path("refresh_token")
        JWTClaimsSet claims2 = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow2, idToken2).JWTClaimsSet

        Response session1Update = Steps.getSessionUpdateResponse(flow1, refreshToken1, flow1.oidcClientA.clientId, flow1.oidcClientA.clientSecret)
        String idToken1Update = session1Update.path("id_token")
        JWTClaimsSet claims1Update = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow1, idToken1Update).JWTClaimsSet

        Response session2Update = Steps.getSessionUpdateResponse(flow2, refreshToken2, flow2.oidcClientA.clientId, flow2.oidcClientA.clientSecret)
        String idToken2Update = session2Update.path("id_token")
        JWTClaimsSet claims2Update = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow2, idToken2Update).JWTClaimsSet

        assertThat("Correct session ID after update", claims1.getClaim("sid"), is(claims1Update.getClaim("sid")))
        assertThat("Correct session ID after update", claims2.getClaim("sid"), is(claims2Update.getClaim("sid")))
        assertThat("Concurrent Sessions do not share session ID", claims1.getClaim("sid"), not(is(claims2.getClaim("sid"))))
        assertThat("Concurrent Sessions do not share session ID", claims1Update.getClaim("sid"), not(is(claims2Update.getClaim("sid"))))
    }

    @Feature("PARALLEL_SESSIONS")
    def "Same user's separate concurrent sessions - first session stays active after logout from second session"() {
        expect:
        Response session1 = Steps.authenticateWithIdCardInGovSso(flow1)
        String idToken1 = session1.path("id_token")
        String refreshToken1 = session1.path("refresh_token")
        JWTClaimsSet claims1 = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow1, idToken1).JWTClaimsSet

        Response session2 = Steps.authenticateWithIdCardInGovSso(flow2)
        String idToken2 = session2.path("id_token")
        Response logout = Steps.logoutSingleClientSession(flow2, idToken2, flow2.oidcClientA.fullLogoutRedirectUrl)

        Response session1Update = Steps.getSessionUpdateResponse(flow1, refreshToken1, flow1.oidcClientA.clientId, flow1.oidcClientA.clientSecret)
        String idToken1Update = session1Update.body.path("id_token")
        JWTClaimsSet claims1Update = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow1, idToken1Update).JWTClaimsSet

        assertThat("Correct logout redirect URL", logout.getHeader("Location"), startsWith(flow2.oidcClientA.fullLogoutRedirectUrl.toString()))
        assertThat("Correct status code", session1Update.getStatusCode(), is(200))
        assertThat("Correct session ID after update", claims1.getClaim("sid"), is(claims1Update.getClaim("sid")))
    }

    @Ignore("GSSO-565")
    @Feature("PARALLEL_SESSIONS")
    def "Same user's separate concurrent sessions - update session with other sessions' refresh token fails"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow1)

        Response session2 = Steps.authenticateWithIdCardInGovSso(flow2)
        String refreshToken2 = session2.path("refresh_token")

        Response UpdateResponse = Steps.getSessionUpdateResponse(flow1, refreshToken2, flow1.oidcClientA.clientId, flow1.oidcClientA.clientSecret)

        assertThat("Correct HTTP status code", UpdateResponse.getStatusCode(), is(400))
        assertThat("Correct error", UpdateResponse.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Correct error message", UpdateResponse.jsonPath().getString("error_message"), is("Ebakorrektne päring."))
    }
}
