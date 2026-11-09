package ee.ria.govsso

import com.nimbusds.jwt.JWTClaimsSet
import ee.ria.govsso.database.SqlQueries
import ee.ria.govsso.model.HydraError
import ee.ria.govsso.util.HydraErrorValidator
import io.qameta.allure.Epic
import io.qameta.allure.Feature
import io.qameta.allure.Story
import io.restassured.response.Response

import java.time.Duration

import static ee.ria.govsso.util.HydraErrorValidator.HINT_SESSION_EXPIRED
import static ee.ria.govsso.util.HydraErrorValidator.HINT_TOKEN_VALIDATION_FAILED
import static org.hamcrest.Matchers.startsWith
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.allOf
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.MatcherAssert.assertThat

@Epic("DATABASE")
@Feature("EXPIRATION")
class ExpirationSpec extends GovSsoOidcSpecification {

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
        Response updateSession = Steps.tryUpdateSession(flow)

        then: "Expected status code is 400 and correct error response is returned"
        HydraErrorValidator.validate(updateSession, HydraError.INVALID_REQUEST, HINT_SESSION_EXPIRED)
    }

    @Story("SESSION_EXPIRATION")
    def "Session update request fails after session max duration"() {
        given: "Create a valid session"
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, createSession.path("id_token")).JWTClaimsSet

        and: "Age the authentication beyond the session max duration"
        SqlQueries.ageTaraAuthentication(sql, claims.getClaim("sid") as String, Duration.ofHours(13))

        when: "Request session update"
        Response updateSession = Steps.tryUpdateSession(flow)

        then:
        HydraErrorValidator.validate(updateSession, HydraError.TOKEN_HOOK_REJECTION, "Hydra session has expired")
    }

    @Story("CONSENT_EXPIRATION")
    def "Session update request fails after consent expiration"() {
        given: "Create a valid session"
        Steps.authenticateWithIdCardInGovSso(flow)

        and: "Expire consent"
        SqlQueries.expireConsent(sql, flow.consentChallenge)

        when: "Request session update"
        Response updateSession = Steps.tryUpdateSession(flow)

        then: "Expected status code is 400 and correct error response is returned"
        HydraErrorValidator.validate(updateSession, HydraError.INVALID_REQUEST, HINT_SESSION_EXPIRED)
    }

    @Story("REFRESH_TOKEN_INACTIVE")
    def "Session update request fails after refresh token expiration"() {
        given: "Create a valid session"
        Steps.authenticateWithIdCardInGovSso(flow)

        and: "Inactivate refresh token"
        SqlQueries.inactivateRefreshToken(sql, flow.consentChallenge)

        when: "Request session update"
        Response updateSession = Steps.tryUpdateSession(flow)

        then: "Expected status code is 401 and correct error response is returned"
        HydraErrorValidator.validate(updateSession, HydraError.TOKEN_INACTIVE, HINT_TOKEN_VALIDATION_FAILED)
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
        assertThat(logout.header("Location"), startsWith(ClientStore.clientA.postLogoutRedirectUri))
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
        assertThat(logout.header("Location"), startsWith(ClientStore.clientA.postLogoutRedirectUri))
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
        assertThat(logout.header("Location"), startsWith(ClientStore.clientA.postLogoutRedirectUri))
    }

    private def expireSession(Flow flow, Response response) {
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, response.body.path("id_token")).JWTClaimsSet
        String sessionId = claims.getClaim("sid")
        SqlQueries.expireSession(sql, sessionId)
    }
}

