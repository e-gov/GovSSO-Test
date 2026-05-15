package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.http.HttpStatus

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is

class SecuredAppSpec extends GovSsoSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Feature("BUSINESS_LOGIC")
    def "Given authentication in secured app client, then update session succeeds"() {
        given:
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.mockSecuredApp)

        when:
        Response updateSession = Steps.getSessionUpdateResponse(flow, flow.refreshToken, ClientStore.mockSecuredApp)

        then:
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, updateSession.body.path("id_token")).JWTClaimsSet
        assertThat("Correct audience value", claims.audience[0], is(ClientStore.mockSecuredApp.clientId))
        assertThat("Correct subject value", claims.subject, is("EE38001085718"))
        assertThat("Correct given name value", claims.getClaim("given_name"), is("JAAK-KRISTJAN"))
    }

    @Feature("BUSINESS_LOGIC")
    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Given authentication in #authClientLabel client, then continuing session in #continueClientLabel client fails"() {
        given:
        Steps.authenticateWithIdCardInGovSso(flow, authClient)

        when:
        Response continueSession = Steps.continueWithExistingSession(flow, continueClient)

        then:
        continueSession.then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body(
                        "error", is("USER_INPUT"),
                        "path", is("/login/init"),
                        "message", is("Ebakorrektne päring."))

        where:
        authClientLabel | authClient                 | continueClientLabel | continueClient
        "secured app"   | ClientStore.mockSecuredApp | "default"           | ClientStore.clientB
        "default"       | ClientStore.clientA        | "secured app"       | ClientStore.mockSecuredApp
        "secured app"   | ClientStore.mockSecuredApp | "secured app"       | ClientStore.mockSecuredApp
    }

    @Feature("BUSINESS_LOGIC")
    @Feature("LOGIN_REAUTHENTICATE_ENDPOINT")
    def "Given authentication in #authClientLabel client, then reauthenticating in #reauthClientLabel client fails"() {
        given:
        Steps.authenticateWithIdCardInGovSso(flow, authClient)

        when:
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, reauthClient)
        Response initLogin = Steps.followRedirect(flow, oidcAuth)

        then:
        initLogin.then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body(
                        "error", is("USER_INPUT"),
                        "path", is("/login/init"),
                        "message", is("Ebakorrektne päring."))

        where:
        authClientLabel | authClient                 | reauthClientLabel | reauthClient
        "secured app"   | ClientStore.mockSecuredApp | "default"         | ClientStore.clientA
        "default"       | ClientStore.clientA        | "secured app"     | ClientStore.mockSecuredApp
        "secured app"   | ClientStore.mockSecuredApp | "secured app"     | ClientStore.mockSecuredApp
    }
}
