package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.junit.jupiter.api.Assertions.assertEquals
import static org.junit.jupiter.api.Assertions.assertNotEquals
import static org.junit.jupiter.api.Assertions.assertTrue

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
        String idToken1 = session1.jsonPath().get("id_token")
        JWTClaimsSet claims1 = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow1, idToken1).getJWTClaimsSet()

        Response session2 = Steps.authenticateWithIdCardInGovSso(flow2)
        String idToken2 = session2.jsonPath().get("id_token")
        JWTClaimsSet claims2 = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow2, idToken2).getJWTClaimsSet()

        Response session1Refresh = Steps.refreshSessionWithDefaults(flow1, idToken1)
        String idToken1Refresh = session1Refresh.jsonPath().get("id_token")
        JWTClaimsSet claims1Refresh = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow1, idToken1Refresh).getJWTClaimsSet()

        Response session2Refresh = Steps.refreshSessionWithDefaults(flow2, idToken2)
        String idToken2Refresh = session2Refresh.jsonPath().get("id_token")
        JWTClaimsSet claims2Refresh = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow2, idToken2Refresh).getJWTClaimsSet()

        assertEquals(claims1.getClaim("sid"), claims1Refresh.getClaim("sid"), "Correct session ID after refresh")
        assertEquals(claims2.getClaim("sid"), claims2Refresh.getClaim("sid"), "Correct session ID after refresh")
        assertNotEquals(claims1.getClaim("sid"), claims2.getClaim("sid"), "Concurrent Sessions do not share session ID")
        assertNotEquals(claims1Refresh.getClaim("sid"), claims2Refresh.getClaim("sid"), "Concurrent Sessions do not share session ID")
    }

    @Feature("PARALLEL_SESSIONS")
    def "Same user's separate concurrent sessions - first session stays active after logout from second session"() {
        expect:
        Response session1 = Steps.authenticateWithIdCardInGovSso(flow1)
        String idToken1 = session1.jsonPath().get("id_token")
        JWTClaimsSet claims1 = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow1, idToken1).getJWTClaimsSet()

        Response createSession = Steps.authenticateWithIdCardInGovSso(flow2)
        String idToken2 = createSession.jsonPath().get("id_token")
        Response logout = Steps.logoutSingleClientSession(flow2, idToken2, flow2.oidcClientA.fullBaseUrl)

        Response refreshSession1 = Steps.refreshSessionWithDefaults(flow1, idToken1)
        String idToken1Refresh = refreshSession1.getBody().jsonPath().get("id_token")
        JWTClaimsSet claims1Refresh = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow1, idToken1Refresh).getJWTClaimsSet()

        assertTrue(logout.getHeader("Location")==(flow2.oidcClientA.fullBaseUrl), "Correct logout redirect URL")
        assertEquals(200, refreshSession1.getStatusCode(), "Session refresh is successful after logout from second session")
        assertEquals(claims1.getClaim("sid"), claims1Refresh.getClaim("sid"), "Correct session ID after refresh")
    }
}
