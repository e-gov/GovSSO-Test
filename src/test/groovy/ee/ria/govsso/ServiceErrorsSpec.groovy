package ee.ria.govsso

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.hamcrest.Matchers.*
import static org.hamcrest.MatcherAssert.assertThat


class ServiceErrorsSpec extends GovSsoSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Feature("ERROR_CONTENT_JSON")
    def "OIDC service error response JSON"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "invalid-client-id", flow.oidcClientA.fullResponseUrl)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response oidcError = Steps.followRedirect(flow, oidcAuth)

        assertThat("Contains error status code", oidcError.jsonPath().getInt("status"), is(400))
        assertThat("Contains path", oidcError.jsonPath().getString("path"), is("/error/oidc"))
        assertThat("Contains error", oidcError.jsonPath().getString("error"), is("USER_INVALID_OIDC_CLIENT"))
        assertThat("Contains message", oidcError.jsonPath().getString("message"), is("Vale <span translate=\"no\">OIDC</span> klient."))
        assertThat("Contains timestamp", !oidcError.jsonPath().getString("timestamp").isEmpty())
        assertThat("Contains incident number", oidcError.jsonPath().getString("incident_nr").size()==32)
    }

    @Feature("ERROR_CONTENT_JSON")
    def "Session service error response JSON"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.put("acr_values", "invalid")
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response sessionError = Steps.followRedirect(flow, oidcAuth)

        assertThat("Contains error status code", sessionError.jsonPath().getInt("status"), is(400))
        assertThat("Contains path", sessionError.jsonPath().getString("path"), is("/login/init"))
        assertThat("Contains error", sessionError.jsonPath().getString("error"), is("USER_INPUT"))
        assertThat("Contains message", sessionError.jsonPath().getString("message"), is("Ebakorrektne päring."))
        assertThat("Contains timestamp", !sessionError.jsonPath().getString("timestamp").isEmpty())
        assertThat("Contains incident number", sessionError.jsonPath().getString("incident_nr").size()==32)
    }
}
