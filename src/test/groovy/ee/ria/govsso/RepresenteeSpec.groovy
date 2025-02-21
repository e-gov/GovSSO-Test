package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.qameta.allure.Step
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static io.restassured.RestAssured.given
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.allOf
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.hasEntry
import static org.hamcrest.Matchers.hasItem
import static org.hamcrest.Matchers.hasItems
import static org.hamcrest.Matchers.hasKey
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.not
import static org.hamcrest.Matchers.startsWith

class RepresenteeSpec extends GovSsoSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Feature("REPRESENTEE_LIST")
    def "Requesting representee_list should return the claim in ID token"() {
        when: "Create session"
        Response token = Steps.authenticateInGovSsoWithScope(flow)
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, token.path("id_token")).JWTClaimsSet

        then:
        assertThat("Correct scope in token response", token.jsonPath().getString("scope"), is("openid representee.* representee_list"))
        assertThat("Correct legal person in representee list", claims.getClaim("representee_list")["list"], hasItem(
                allOf(
                        hasEntry("name", "Small Company"),
                        hasEntry("sub", "EE97007088"),
                        hasEntry("type", "LEGAL_PERSON"))))
        assertThat("Correct natural person in representee list", claims.getClaim("representee_list")["list"], hasItem(
                allOf(
                        hasEntry("family_name", "TESTKASUTAJA KAKS"),
                        hasEntry("given_name", "TARA GOVSSO"),
                        hasEntry("sub", "EE10303030002"),
                        hasEntry("type", "NATURAL_PERSON"))))
        assertThat("Representee list is up-to-date", claims.getClaim("representee_list")["status"], is("REPRESENTEE_LIST_CURRENT"))
    }

    @Feature("REPRESENTEE_LIST")
    def "Requesting session update with representee_list scope should return the claim in ID token"() {
        given: "Create session"
        Steps.authenticateInGovSsoWithScope(flow)

        when: "Update session with representee_list scope"
        Response updateSession = Steps.getSessionUpdateResponseWithScope(flow, "openid representee_list")
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, updateSession.path("id_token")).JWTClaimsSet

        then:
        assertThat("Correct HTTP status code", updateSession.statusCode, is(200))
        assertThat("Correct legal person in representee list", claims.getClaim("representee_list")["list"], hasItem(
                allOf(
                        hasEntry("name", "Small Company"),
                        hasEntry("sub", "EE97007088"),
                        hasEntry("type", "LEGAL_PERSON"))))
        assertThat("Correct natural person in representee list", claims.getClaim("representee_list")["list"], hasItem(
                allOf(
                        hasEntry("family_name", "TESTKASUTAJA KAKS"),
                        hasEntry("given_name", "TARA GOVSSO"),
                        hasEntry("sub", "EE10303030002"),
                        hasEntry("type", "NATURAL_PERSON"))))
        assertThat("Representee list is up-to-date", claims.getClaim("representee_list")["status"], is("REPRESENTEE_LIST_CURRENT"))
    }

    @Feature("REPRESENTEE")
    def "Requesting session update with valid representee scope #scope should return representee claims in ID token"() {
        given: "Create session"
        Steps.authenticateInGovSsoWithScope(flow)

        when: "Update session with valid representee scope"
        Response updateSession = Steps.getSessionUpdateResponseWithScope(flow, "openid " + scope)
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, updateSession.path("id_token")).JWTClaimsSet

        then:
        assertThat("Correct representee name", claims.getClaim("representee")["name"], is(name))
        assertThat("Correct representee family name", claims.getClaim("representee")["family_name"], is(familyName))
        assertThat("Correct representee family name", claims.getClaim("representee")["given_name"], is(givenName))
        assertThat("Correct representee status", claims.getClaim("representee")["status"], is("REQUESTED_REPRESENTEE_CURRENT"))
        assertThat("Correct representee subject", claims.getClaim("representee")["sub"], is(subject))
        assertThat("Correct representee type", claims.getClaim("representee")["type"], is(type))
        assertThat("Correct representee mandates", claims.getClaim("representee")["mandates"], hasItems(allOf(hasEntry("role", "ARGUMENT_CLINIC_DEMO:ARGUER")), allOf(hasEntry("role", role))))

        where:
        scope                       || name            | familyName          | givenName     | subject         | type             | role
        "representee.EE97007088"    || "Small Company" | null                | null          | "EE97007088"    | "LEGAL_PERSON"   | "PAASUKE:ARGUMENT_CLINIC_DEMO:CREDENTIALS_MANAGER"
        "representee.EE10303030002" || null            | "TESTKASUTAJA KAKS" | "TARA GOVSSO" | "EE10303030002" | "NATURAL_PERSON" | "ARGUMENT_CLINIC_DEMO:ARGUER"
    }

    @Feature("REPRESENTEE")
    def "Requesting session update with invalid representee scope should return REQUESTED_REPRESENTEE_NOT_ALLOWED claim in ID and access tokens"() {
        given: "Create session"
        Steps.authenticateInGovSsoWithScope(flow)

        when: "Update session with invalid representee scope"
        Response updateSession = Steps.getSessionUpdateResponseWithScope(flow, "openid representee.EE12345678901")
        JWTClaimsSet claimsIdToken = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, updateSession.path("id_token")).JWTClaimsSet
        JWTClaimsSet claimsAccessToken = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, updateSession.path("access_token")).JWTClaimsSet


        then:
        assertThat("Correct claim in ID Token", claimsIdToken.getClaim("representee")["status"], is("REQUESTED_REPRESENTEE_NOT_ALLOWED"))
        assertThat("Correct claim in access token", claimsAccessToken.getClaim("representee")["status"], is("REQUESTED_REPRESENTEE_NOT_ALLOWED"))
    }

    @Feature("REPRESENTEE")
    def "Representee claims in #token should update after switching representative"() {
        given: "Create session"
        Steps.authenticateInGovSsoWithScope(flow)

        when: "Update session with representee.EE97007088"
        Steps.getSessionUpdateResponseWithScope(flow, "openid representee.EE97007088")

        and: "Update session with representee.EE10303030002"
        Response updateSession = Steps.getSessionUpdateResponseWithScope(flow, "openid representee.EE10303030002")
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, updateSession.path(token)).JWTClaimsSet

        then:
        assertThat("Does not contain name key", claims.getClaims(), not(hasKey("name")))
        assertThat("Correct representee family name", claims.getClaim("representee")["family_name"], is("TESTKASUTAJA KAKS"))
        assertThat("Correct representee family name", claims.getClaim("representee")["given_name"], is("TARA GOVSSO"))
        assertThat("Correct representee status", claims.getClaim("representee")["status"], is("REQUESTED_REPRESENTEE_CURRENT"))
        assertThat("Correct representee subject", claims.getClaim("representee")["sub"], is("EE10303030002"))
        assertThat("Correct representee type", claims.getClaim("representee")["type"], is("NATURAL_PERSON"))
        assertThat("Correct representee mandates", claims.getClaim("representee")["mandates"], hasItems(
                allOf(hasEntry("role", "ARGUMENT_CLINIC_DEMO:ARGUER")), hasEntry("role", "ARGUMENT_CLINIC_DEMO:COMPLAINER")))

        where:
        token          | _
        "id_token"     | _
        "access_token" | _
    }

    @Feature("REPRESENTEE")
    def "Requesting session update with both representee and representee_list scope should return representee and representee_list claims in ID token"() {
        given: "Create session"
        Steps.authenticateInGovSsoWithScope(flow)

        when: "Update session with representee and representee_list scope"
        Response updateSession = Steps.getSessionUpdateResponseWithScope(flow, "openid representee.EE97007088 representee_list")
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, updateSession.path("id_token")).JWTClaimsSet

        then:
        assertThat("Correct representee name", claims.getClaim("representee")["name"], is("Small Company"))
        assertThat("Correct representee status", claims.getClaim("representee")["status"], is("REQUESTED_REPRESENTEE_CURRENT"))
        assertThat("Correct representee subject", claims.getClaim("representee")["sub"], is("EE97007088"))
        assertThat("Correct representee type", claims.getClaim("representee")["type"], is("LEGAL_PERSON"))
        assertThat("Correct representee mandates", claims.getClaim("representee")["mandates"], hasItems(
                allOf(hasEntry("role", "ARGUMENT_CLINIC_DEMO:ARGUER")), hasEntry("role", "PAASUKE:ARGUMENT_CLINIC_DEMO:CREDENTIALS_MANAGER")))
        assertThat("Correct legal person in representee list", claims.getClaim("representee_list")["list"], hasItem(
                allOf(
                        hasEntry("name", "Small Company"),
                        hasEntry("sub", "EE97007088"),
                        hasEntry("type", "LEGAL_PERSON"))))
        assertThat("Correct natural person in representee list", claims.getClaim("representee_list")["list"], hasItem(
                allOf(
                        hasEntry("family_name", "TESTKASUTAJA KAKS"),
                        hasEntry("given_name", "TARA GOVSSO"),
                        hasEntry("sub", "EE10303030002"),
                        hasEntry("type", "NATURAL_PERSON"))))
    }

    @Feature("REPRESENTEE_LIST")
    def "Requesting representee_list should not return the claim in access token"() {
        when: "Create session"
        Response token = Steps.authenticateInGovSsoWithScope(flow)
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, token.path("access_token")).JWTClaimsSet

        then:
        assertThat("Access token should not have representee_list claim", claims.getClaims(), not(hasKey("representee_list")))
    }

    @Feature("REPRESENTEE_LIST")
    def "Requesting #scope should return the representee claims in access token"() {
        given: "Create session"
        Steps.authenticateInGovSsoWithScope(flow)

        when: "Update session with valid representee scope"
        Response updateSession = Steps.getSessionUpdateResponseWithScope(flow, "openid " + scope)
        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, updateSession.path("access_token")).JWTClaimsSet

        then:
        assertThat("Correct representee name", claims.getClaim("representee")["name"], is(name))
        assertThat("Correct representee family name", claims.getClaim("representee")["family_name"], is(familyName))
        assertThat("Correct representee family name", claims.getClaim("representee")["given_name"], is(givenName))
        assertThat("Correct representee status", claims.getClaim("representee")["status"], is("REQUESTED_REPRESENTEE_CURRENT"))
        assertThat("Correct representee subject", claims.getClaim("representee")["sub"], is(subject))
        assertThat("Correct representee type", claims.getClaim("representee")["type"], is(type))
        assertThat("Correct representee mandates", claims.getClaim("representee")["mandates"], hasItems(allOf(hasEntry("role", "ARGUMENT_CLINIC_DEMO:ARGUER")), allOf(hasEntry("role", role))))

        where:
        scope                       || name            | familyName          | givenName     | subject         | type             | role
        "representee.EE97007088"    || "Small Company" | null                | null          | "EE97007088"    | "LEGAL_PERSON"   | "PAASUKE:ARGUMENT_CLINIC_DEMO:CREDENTIALS_MANAGER"
        "representee.EE10303030002" || null            | "TESTKASUTAJA KAKS" | "TARA GOVSSO" | "EE10303030002" | "NATURAL_PERSON" | "ARGUMENT_CLINIC_DEMO:ARGUER"
    }

    @Feature("REPRESENTEE")
    @Feature("REPRESENTEE_LIST")
    def "Requesting authentication with #scopeValue scope without matching client configuration should direct to invalid scope error page"() {
        when: "Request authentication with not registered scope"
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap << [scope: "openid " + scopeValue]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        then:
        assertThat("Correct HTTP response code", oidcAuth.statusCode, is(303))
        assertThat("Correct location header", oidcAuth.headers.get("Location").toString(), containsString("The+requested+scope+is+invalid"))

        where:
        scopeValue         | _
        "representee.*"    | _
        "representee_list" | _
    }

    @Feature("REPRESENTEE")
    def "Requesting session update with valid representee without representee scope during authentication should fail"() {
        given: "Create session without representee.* scope"
        Steps.authenticateInGovSsoWithScope(flow, scope)

        when: "Update session with valid representee scope"
        Response updateSession = Steps.getSessionUpdateResponseWithScope(flow, "openid representee.EE97007088")

        then:
        assertThat("Correct HTTP status code", updateSession.statusCode, is(500))

        where:
        scope                     | _
        "openid"                  | _
        "openid representee_list" | _
    }

    @Feature("REPRESENTEE")
    @Feature("LOGOUT")
    def "Requesting POST logout with id_token_hint as a form parameter should redirect to session service logout init. Authentication scope #scope"() {
        given: "Create session"
        Steps.authenticateInGovSsoWithScope(flow, scope)

        when: "Start logout"
        Response initLogout = postLogoutRequestWithFormParams(flow)

        then:
        assertThat("Correct HTTP status code", initLogout.statusCode, is(302) )
        assertThat("Correct redirect URL", initLogout.header("location"), startsWith(flow.sessionService.fullLogoutInitUrl + "?logout_challenge="))

        where:
        scope                                   | _
        "openid"                                | _
        "openid representee_list"               | _
        "openid representee_list representee.*" | _
    }

    @Feature("REPRESENTEE")
    @Feature("LOGOUT")
    def "Requesting POST logout with id_token_hint as a query parameter should redirect to OIDC error. Authentication scope #scope"() {
        given: "Create session"
        Steps.authenticateInGovSsoWithScope(flow, scope)

        when: "Start logout"
        Response initLogout = postLogoutRequestWithQueryParams(flow)

        then:
        assertThat("Correct HTTP status code", initLogout.statusCode, is(302) )
        assertThat("Correct redirect error URL", initLogout.header("location"), is("/error/oidc?error=invalid_request&" +
                "error_description=The%20%27id_token_hint%27%20query%20parameter%20is%20not%20allowed%20when%20" +
                "using%20logout%20request%20with%20http%20POST%20method%2C%20it%20must%20be%20passed%20as%20a%20form%20parameter"))

        where:
        scope                                   | _
        "openid"                                | _
        "openid representee_list"               | _
        "openid representee_list representee.*" | _
    }

    @Feature("REPRESENTEE")
    @Feature("LOGOUT")
    def "Requesting GET logout with id_token_hint containing representee_list as a query parameter should redirect to OIDC error."() {
        given: "Create session"
        Steps.authenticateInGovSsoWithScope(flow)

        when: "Start logout"
        Map queryParams = [post_logout_redirect_uri: flow.oidcClientB.fullLogoutRedirectUrl,
                           ui_locales              : "en",
                           id_token_hint           : flow.idToken]
        Response initLogout = Requests.getRequestWithParams(flow, flow.ssoOidcService.fullLogoutUrl, queryParams)


        then:
        assertThat("Correct HTTP status code", initLogout.statusCode, is(302) )
        assertThat("Correct redirect error URL", initLogout.header("location"), is("/error/oidc?error=invalid_request&" +
                "error_description=Logout%20request%20must%20use%20POST%20method%20if%20the%20id%20token%20" +
                "from%20%27id_token_hint%27%20parameter%20contains%20a%20%27representee_list%27%20claim"))
    }

    @Step("POST logout request with query params")
    static Response postLogoutRequestWithQueryParams(Flow flow) {
        return given()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .filter(flow.cookieFilter)
                .queryParams([post_logout_redirect_uri: flow.oidcClientB.fullLogoutRedirectUrl,
                              ui_locales              : "en",
                              id_token_hint           : flow.idToken])
                .log().cookies()
                .post(flow.ssoOidcService.fullLogoutUrl)
    }

    @Step("POST logout request with form params")
    static Response postLogoutRequestWithFormParams(Flow flow) {
        return given()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .filter(flow.cookieFilter)
                .formParams([post_logout_redirect_uri: flow.oidcClientB.fullLogoutRedirectUrl,
                             ui_locales              : "en",
                             id_token_hint           : flow.idToken])
                .log().cookies()
                .post(flow.ssoOidcService.fullLogoutUrl)
    }
}

