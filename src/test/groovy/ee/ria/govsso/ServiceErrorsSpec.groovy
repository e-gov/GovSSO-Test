package ee.ria.govsso

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.junit.jupiter.api.Assertions.assertEquals
import static org.junit.jupiter.api.Assertions.assertTrue


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

        assertEquals(400, oidcError.jsonPath().getInt("status"), "Contains error status code")
        assertEquals("/error/oidc", oidcError.jsonPath().getString("path"), "Contains path")
        assertEquals("USER_INVALID_OIDC_CLIENT", oidcError.jsonPath().getString("error"), "Contains error")
        assertEquals("Vale OIDC klient.", oidcError.jsonPath().getString("message"), "Contains message")
        assertTrue(!oidcError.jsonPath().getString("timestamp").isEmpty(), "Contains timestamp")
        assertTrue(oidcError.jsonPath().getString("incident_nr").size()==32, "Contains incident number")
    }

    @Feature("ERROR_CONTENT_JSON")
    def "Session service error response JSON"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.put("acr_values", "invalid")
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response sessionError = Steps.followRedirect(flow, oidcAuth)

        assertEquals(400, sessionError.jsonPath().getInt("status"), "Contains error status code")
        assertEquals("/login/init", sessionError.jsonPath().getString("path"), "Contains path")
        assertEquals("USER_INPUT", sessionError.jsonPath().get("error"), "Contains error")
        assertEquals("Ebakorrektne päring.", sessionError.jsonPath().get("message"), "Contains message")
        assertTrue(!sessionError.jsonPath().getString("timestamp").isEmpty(), "Contains timestamp")
        assertTrue(sessionError.jsonPath().getString("incident_nr").size()==32, "Contains incident number")
    }
}
