package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import ee.ria.govsso.database.DatabaseConnection
import ee.ria.govsso.database.SqlQueries
import groovy.sql.Sql
import io.qameta.allure.Epic
import io.qameta.allure.Feature
import io.qameta.allure.Story
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.junit.jupiter.api.AfterEach

import static org.hamcrest.Matchers.startsWith
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.allOf
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.MatcherAssert.assertThat

@Epic("DATABASE")
@Feature("EXPIRATION")
class ExpirationSpec extends  GovSsoSpecification {

    static final ERROR_EXPIRED = "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Authentication session not found or expired."
    static final ERROR_INACTIVE = "Token is inactive because it is malformed, expired or otherwise invalid. Token validation failed."

    Flow flow = new Flow(props)
    Sql sql = null

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
        sql = DatabaseConnection.getSql(flow)
    }

    @AfterEach
    def cleanup() {
        sql.close()
    }

    @Story("REFRESH_TOKEN_INACTIVE")
    def "Authentication request succeeds after refresh token expiration"() {
        given: "Create a valid session"
        Steps.authenticateWithIdCardInGovSso(flow)

        and: "Inactivate refresh token"
        SqlQueries.inactivateRefreshToken(sql, flow.consentChallenge)

        when: "Authenticate again"
        Response authenticate = Steps.startAuthenticationInSsoOidc(flow)

        then: "Expected status code is 302 and response location header holds correct redirect URL"
        assertThat(authenticate.statusCode, is(302))
        assertThat(authenticate.header("Location"), startsWith(flow.sessionService.fullInitUrl))
    }

    @Story("SESSION_EXPIRATION")
    def "Session update request fails after session expiration"() {
        given: "Create a valid session"
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)

        and: "Expire session"
        expireSession(flow, createSession)

        when: "Request session update"
        Response updateSession = Steps.getSessionUpdateResponse(flow)

        then: "Expected status code is 400 and correct error response is returned"
        assertThat(updateSession.statusCode, is(400))
        assertThat(updateSession.jsonPath().getString("error"), is("invalid_request"))
        assertThat(updateSession.jsonPath().getString("error_description"), is(ERROR_EXPIRED))
    }

    @Story("CONSENT_EXPIRATION")
    def "Session update request fails after consent expiration"() {
        given: "Create a valid session"
        Steps.authenticateWithIdCardInGovSso(flow)

        and: "Expire consent"
        SqlQueries.expireConsent(sql, flow.consentChallenge)

        when: "Request session update"
        Response updateSession = Steps.getSessionUpdateResponse(flow)

        then: "Expected status code is 400 and correct error response is returned"
        assertThat(updateSession.statusCode, is(400))
        assertThat(updateSession.jsonPath().getString("error"), is("invalid_request"))
        assertThat(updateSession.jsonPath().getString("error_description"), is(ERROR_EXPIRED))
    }

    @Story("REFRESH_TOKEN_INACTIVE")
    def "Session update request fails after refresh token expiration"() {
        given: "Create a valid session"
        Steps.authenticateWithIdCardInGovSso(flow)

        and: "Inactivate refresh token"
        SqlQueries.inactivateRefreshToken(sql, flow.consentChallenge)

        when: "Request session update"
        Response updateSession = Steps.getSessionUpdateResponse(flow)

        then: "Expected status code is 400 and correct error response is returned"
        assertThat(updateSession.statusCode, is(401))
        assertThat(updateSession.jsonPath().getString("error"), is("token_inactive"))
        assertThat(updateSession.jsonPath().getString("error_description"), is(ERROR_INACTIVE))
    }

    @Story("SESSION_EXPIRATION")
    def "Session continuation flow directs to authentication after session expiration"() {
        given: "Create a valid session"
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)

        and: "Expire session"
        expireSession(flow, createSession)

        when: "Request session continuation"
        Response continueSession = Steps.continueWithExistingSession(flow)

        then: "Expected status code is 302 and user is directed to authentication"
        assertThat(continueSession.statusCode, is(302))
        assertThat(continueSession.header("Location"), allOf(containsString("/oidc/authorize?"), containsString("client_id=govsso")))
    }

    @Story("CONSENT_EXPIRATION")
    def "Session continuation flow directs to authentication after consent expiration"() {
        given: "Create a valid session"
        Steps.authenticateWithIdCardInGovSso(flow)

        and: "Expire consent"
        SqlQueries.expireConsent(sql, flow.consentChallenge)

        when: "Request session continuation"
        Response continueSession = Steps.continueWithExistingSession(flow)

        Response oidcAuth = Steps.followRedirect(flow, continueSession)
        Response loginInit = Steps.followRedirect(flow, oidcAuth)

        then: "Expected status code is 302 and user is directed to authentication"
        assertThat(loginInit.statusCode, is(302))
        assertThat(loginInit.header("Location"), allOf(containsString("/oidc/authorize?"), containsString("client_id=govsso")))
    }

    @Story("SESSION_EXPIRATION")
    def "Logout request succeeds after session expiration"() {
        given: "Create a valid session"
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)

        and: "Expire session"
        expireSession(flow, createSession)

        when: "Request logout"
        Response logout = Steps.logoutSingleClientSession(flow)

        then: "Expected status code is 302 and response location header holds correct logout redirect URL"
        assertThat(logout.statusCode, is(302))
        assertThat(logout.header("Location"), startsWith(flow.oidcClientA.fullLogoutRedirectUrl))
    }

    @Story("CONSENT_EXPIRATION")
    def "Logout request succeeds after consent expiration"() {
        given: "Create a valid session"
        Steps.authenticateWithIdCardInGovSso(flow)

        and: "Expire consent"
        SqlQueries.expireConsent(sql, flow.consentChallenge)

        when: "Request logout"
        Response logout = Steps.logoutSingleClientSession(flow)

        then: "Expected status code is 302 and response location header holds correct logout redirect URL"
        assertThat(logout.statusCode, is(302))
        assertThat(logout.header("Location"), startsWith(flow.oidcClientA.fullLogoutRedirectUrl))
    }

    @Story("REFRESH_TOKEN_INACTIVE")
    def "Logout request succeeds after refresh token expiration"() {
        given: "Create a valid session"
        Steps.authenticateWithIdCardInGovSso(flow)

        and: "Inactivate refresh token"
        SqlQueries.inactivateRefreshToken(sql, flow.consentChallenge)

        when: "Request session update"
        Response logout = Steps.logoutSingleClientSession(flow)

        then: "Expected status code is 302 and response location header holds correct logout redirect URL"
        assertThat(logout.statusCode, is(302))
        assertThat(logout.header("Location"), startsWith(flow.oidcClientA.fullLogoutRedirectUrl))
    }

    private def expireSession(Flow flow, Response response) {
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, response.body.path("id_token")).JWTClaimsSet
        String sessionId = claims.getClaim("sid")
        SqlQueries.expireSession(sql, sessionId)
    }
}

