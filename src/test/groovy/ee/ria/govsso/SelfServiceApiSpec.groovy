package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import ee.ria.govsso.database.DatabaseConnection
import ee.ria.govsso.database.SqlQueries
import groovy.sql.Sql
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll

import java.time.Instant
import java.time.temporal.ChronoUnit

import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.not
import static org.hamcrest.Matchers.allOf
import static org.hamcrest.Matchers.hasEntry
import static org.hamcrest.Matchers.hasItem
import static org.hamcrest.Matchers.hasSize
import static org.hamcrest.Matchers.everyItem
import static org.hamcrest.Matchers.emptyString
import static org.hamcrest.MatcherAssert.assertThat

class SelfServiceApiSpec extends GovSsoSpecification {

    static final SUBJECT_ENDPOINT = "/EE38001085718"
    static final NONVALID_SESSION_UUID = "/76474092-655e-4897-8aba-d6bb568fee4d"

    Flow flow1 = new Flow(props)
    Flow flow2 = new Flow(props)
    Sql sql = null

    def setup() {
        flow1.cookieFilter = new CookieFilter()
        flow2.cookieFilter = new CookieFilter()
        flow1.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow1.ssoOidcService.fullConfigurationUrl)
        flow2.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow2.ssoOidcService.fullConfigurationUrl)
        flow1.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow1.ssoOidcService.fullJwksUrl))
        flow2.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow2.ssoOidcService.fullJwksUrl))
        Requests.deleteRequest(flow1.sessionService.baseSessionsUrl + SUBJECT_ENDPOINT)
    }

    @Feature("SELF_SERVICE_API")
    def "GET sessions returns information of valid sessions for subject"() {
        given: "Create a session"
        Response session = Steps.authenticateWithIdCardInGovSso(flow1)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow1, session.body.path("id_token")).JWTClaimsSet
        String sessionId = [claims.getClaim("sid")]
        Instant requestedAt = claims.getDateClaim("rat").toInstant()

        sql = DatabaseConnection.getSql(flow1)
        Integer consentRememberFor = SqlQueries.getConsentRememberFor(sql, flow1.consentChallenge)
        Instant expiresAt = requestedAt.plusSeconds(consentRememberFor)
        Instant lastUpdatedAt = expiresAt.minusSeconds(900)

        when: "GET session information"
        Response sessionInfo = Requests.getRequest(flow1.sessionService.baseSessionsUrl + SUBJECT_ENDPOINT)

        then: "GET request is successful and correct response payload is returned"
        assertThat("Correct status code", sessionInfo.statusCode(), is(200))
        assertThat("User has a single session with correct session ID", sessionInfo.path("session_id").toString(), is(sessionId))
        assertThat("Authenticated_at is present", sessionInfo.path("authenticated_at[0]").toString(), is(requestedAt.toString()))
        assertThat("Ip_address is present", sessionInfo.path("ip_addresses"), allOf(hasSize(1), everyItem(not(emptyString()))))
        assertThat("Correct user_agent", sessionInfo.path("user_agent[0]"), is("Test User-Agent"))
        assertThat("Correct client_names values", sessionInfo.path("services.client_names[0][0]"), allOf(hasEntry("et", "Teenusenimi A"), hasEntry("en", "Service name A"), hasEntry("ru", "Название службы A")))
        assertThat("Correct services.authenticated_at value", sessionInfo.path("services.authenticated_at[0][0]").toString(), is(requestedAt.toString()))
        assertThat("Correct services.expires_at value", sessionInfo.path("services.expires_at[0][0]").toString(), is(expiresAt.toString()))
        assertThat("Correct services.last_updated_at value", sessionInfo.path("services.last_updated_at[0][0]").toString(), is(lastUpdatedAt.toString()))
    }

    @Feature("SELF_SERVICE_API")
    def "GET sessions returns valid information after session update"() {
        given: "Create a session"
        Response session = Steps.authenticateWithIdCardInGovSso(flow1)
        String refreshToken = session.path("refresh_token")

        and: "GET session information"
        Response sessionInfo1 = Requests.getRequest(flow1.sessionService.baseSessionsUrl + SUBJECT_ENDPOINT)

        //Sleep for 1 second to avoid session update finishing during the same second the original session was created.
        sleep 1000

        and: "Update session"
        Steps.getSessionUpdateResponse(flow1, refreshToken, flow1.oidcClientA.clientId, flow1.oidcClientA.clientSecret)

        when: "GET updated session information"
        Response sessionInfo2 = Requests.getRequest(flow1.sessionService.baseSessionsUrl + SUBJECT_ENDPOINT)

        then: "Session information is updated correctly"
        assertThat("authenticated_at stays the same", sessionInfo2.path("authenticated_at[0]").toString(), is(sessionInfo1.path("authenticated_at[0]").toString()))
        assertThat("services.authenticated_at is updated", sessionInfo2.path("services.authenticated_at[0][0]") == (sessionInfo1.path("services.authenticated_at[0][0]")))
        assertThat("services.expires_at is updated", sessionInfo2.path("services.expires_at[0][0]") > sessionInfo1.path("services.expires_at[0][0]"))
        assertThat("services.last_updated_at is updated", sessionInfo2.path("services.last_updated_at[0][0]") > sessionInfo1.path("services.last_updated_at[0][0]"))
    }

    @Feature("SELF_SERVICE_API")
    def "GET sessions returns valid information after user logs in to same service twice in the same session"() {
        given: "Create a session"
        Steps.authenticateWithIdCardInGovSso(flow1)

        and: "GET session information"
        Response sessionInfo1 = Requests.getRequest(flow1.sessionService.baseSessionsUrl + SUBJECT_ENDPOINT)

        //Sleep for 1 second to avoid session continuation finishing during the same second the original session was created.
        sleep 1000

        and: "Log in to same client"
        Steps.continueWithExistingSession(flow1, flow1.oidcClientA.clientId, flow1.oidcClientA.clientSecret, flow1.oidcClientA.fullResponseUrl)

        when: "GET updated session information"
        Response sessionInfo2 = Requests.getRequest(flow1.sessionService.baseSessionsUrl + SUBJECT_ENDPOINT)

        then: "Session information is updated correctly"
        assertThat("Authenticated_at stays the same", sessionInfo2.path("authenticated_at[0]").toString(), is(sessionInfo1.path("authenticated_at[0]").toString()))
        assertThat("Services.authenticated_at is updated", sessionInfo2.path("services.authenticated_at[0][0]") > (sessionInfo1.path("services.authenticated_at[0][0]")))
        assertThat("Services.expires_at is updated", sessionInfo2.path("services.expires_at[0][0]") > sessionInfo1.path("services.expires_at[0][0]"))
        assertThat("Services.last_updated_at is updated", sessionInfo2.path("services.last_updated_at[0][0]") > sessionInfo1.path("services.last_updated_at[0][0]"))
    }

    @Feature("SELF_SERVICE_API")
    def "GET sessions returns valid information after log out from one service"() {
        given: "Create a session"
        Steps.authenticateWithIdCardInGovSso(flow1)

        and: "Continue session"
        Response continueSession = Steps.continueWithExistingSession(flow1, flow1.oidcClientB.clientId, flow1.oidcClientB.clientSecret, flow1.oidcClientB.fullResponseUrl)
        String idToken = continueSession.path("id_token")

        and: "Logout from one client"
        Steps.logout(flow1, idToken, flow1.oidcClientB.fullLogoutRedirectUrl, flow1.sessionService.fullLogoutContinueSessionUrl)

        //Sleep for 1 second to allow information to update before requesting session information.
        sleep 1000

        when: "GET session information"
        Response sessionInfo = Requests.getRequest(flow1.sessionService.baseSessionsUrl + SUBJECT_ENDPOINT)

        then: "Session information is updated correctly"
        assertThat("Logged out client is present in session info", sessionInfo.path("services.client_names[0][0]"), hasEntry("et", "Teenusenimi B"))
        assertThat("Services.expires_at is same value as services.last_updated_at", sessionInfo.path("services[0].expires_at[0]") == sessionInfo.path("services[0].last_updated_at[0]"))
    }

    @Feature("SELF_SERVICE_API")
    def "DELETE specific session"() {
        given: "Create two separate sessions for same user"
        Response session1 = Steps.authenticateWithIdCardInGovSso(flow1)
        Response session2 = Steps.authenticateWithIdCardInGovSso(flow2)

        String idToken1 = session1.path("id_token").toString()
        JWTClaimsSet claims1 = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow1, idToken1).JWTClaimsSet
        String session1Id = claims1.getClaim("sid")

        String idToken2 = session2.path("id_token").toString()
        JWTClaimsSet claims2 = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow2, idToken2).JWTClaimsSet
        String session2Id = [claims2.getClaim("sid")]

        when: "DELETE specific session and request users' sessions information"
        Response delete = Requests.deleteRequest(flow1.sessionService.baseSessionsUrl + SUBJECT_ENDPOINT + "/" + session1Id)
        Response sessionInfo = Requests.getRequest(flow1.sessionService.baseSessionsUrl + SUBJECT_ENDPOINT)

        then: "DELETE request is successful and user's other session stays active"
        assertThat("DELETE request is successful", delete.statusCode(), is(200))
        assertThat("Users' sessions do not include deleted session", sessionInfo.path("session_id"), not(hasItem(session1Id)))
        assertThat("Users' sessions include still active session", sessionInfo.path("session_id").toString(), is(session2Id))
    }

    @Feature("SELF_SERVICE_API")
    def "DELETE all sessions for a specific user"() {
        given: "Create two separate sessions for same user"
        Steps.authenticateWithIdCardInGovSso(flow1)
        Steps.authenticateWithIdCardInGovSso(flow2)

        when: "DELETE all sessions for user"
        Response delete = Requests.deleteRequest(flow1.sessionService.baseSessionsUrl + SUBJECT_ENDPOINT)
        Response sessionInfo = Requests.getRequest(flow1.sessionService.baseSessionsUrl + SUBJECT_ENDPOINT)

        then: "DELETE request is successful and user has no active sessions"
        assertThat("Correct status code", delete.statusCode(), is(200))
        assertThat("User has no active sessions", sessionInfo.body.asString(), is("[]"))
    }

    @Unroll
    @Feature("SELF_SERVICE_API")
    def "DELETE nonexistent sessions"() {
        when: "DELETE #endpointDescription for user"
        Response sessions = Requests.getRequest(flow1.sessionService.baseSessionsUrl + SUBJECT_ENDPOINT)
        Response delete = Requests.deleteRequest(flow1.sessionService.baseSessionsUrl + endpoint)

        then: "User has no active sessions and DELETE request is successful"
        assertThat("User has no active sessions", sessions.body.asString(), is("[]"))
        assertThat("Correct status code", delete.statusCode(), is(200))

        where:
        endpoint                                 | endpointDescription
        SUBJECT_ENDPOINT                         | "all sessions"
        SUBJECT_ENDPOINT + NONVALID_SESSION_UUID | "specific session"
    }

    @Unroll
    @Feature("SELF_SERVICE_API")
    def "Unsupported request type: #requestType for specific session endpoint returns error"() {
        when: "Request session endpoint with unsupported request type"
        Response response = Requests.requestWithType(requestType, flow1.sessionService.baseSessionsUrl + SUBJECT_ENDPOINT + NONVALID_SESSION_UUID)

        then: "Request type: #requestType is unsuccessful and correct error information is returned"
        assertThat("Correct status code", response.statusCode(), is(500))
        assertThat("Correct path", response.jsonPath().getString("path"), is(flow1.sessionService.sessionsUrl + SUBJECT_ENDPOINT + NONVALID_SESSION_UUID))
        assertThat("Correct error", response.jsonPath().getString("error"), is("TECHNICAL_GENERAL"))
        assertThat("Correct error message", response.jsonPath().getString("message"), is("Protsess ebaõnnestus tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))

        where:
        requestType | _
        "POST"      | _
        "PATCH"     | _
        "PUT"       | _
        "GET"       | _
    }

    @Unroll
    @Feature("SELF_SERVICE_API")
    def "Unsupported request type: #requestType for subject endpoint returns error"() {
        when: "Request sessions endpoint with unsupported request type"
        Response sessions = Requests.requestWithType(requestType, flow1.sessionService.baseSessionsUrl + SUBJECT_ENDPOINT)

        then: "Request type: #requestType is unsuccessful and correct error information is returned"
        assertThat("Correct status code", sessions.statusCode(), is(500))
        assertThat("Correct path", sessions.jsonPath().getString("path"), is(flow1.sessionService.sessionsUrl + SUBJECT_ENDPOINT))
        assertThat("Correct error", sessions.jsonPath().getString("error"), is("TECHNICAL_GENERAL"))
        assertThat("Correct error message", sessions.jsonPath().getString("message"), is("Protsess ebaõnnestus tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))

        where:
        requestType | _
        "POST"      | _
        "PATCH"     | _
        "PUT"       | _
    }
}
