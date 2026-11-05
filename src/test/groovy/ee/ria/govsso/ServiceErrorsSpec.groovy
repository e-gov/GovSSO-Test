package ee.ria.govsso

import ee.ria.govsso.model.Client
import ee.ria.govsso.model.ErrorMessage
import ee.ria.govsso.util.ErrorValidator
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

class ServiceErrorsSpec extends GovSsoSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Feature("ERROR_CONTENT_JSON")
    def "OIDC service error response JSON"() {
        expect:
        Client invalidClient = new Client(clientId: "invalid-client-id", redirectUris: ClientStore.clientA.redirectUris)
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, invalidClient)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response oidcError = Steps.followRedirect(flow, oidcAuth)

        ErrorValidator.validate(oidcError, ErrorMessage.USER_INVALID_OIDC_CLIENT, "/error/oidc")
    }

    @Feature("ERROR_CONTENT_JSON")
    def "Session service error response JSON"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap.put("acr_values", "invalid")
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response sessionError = Steps.followRedirect(flow, oidcAuth)

        ErrorValidator.validate(sessionError, ErrorMessage.USER_INPUT, "/login/init")
    }
}
