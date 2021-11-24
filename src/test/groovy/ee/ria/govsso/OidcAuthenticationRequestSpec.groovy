package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import org.hamcrest.Matchers
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Ignore

import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.startsWith
import static org.junit.jupiter.api.Assertions.*
import static org.hamcrest.MatcherAssert.assertThat

class OidcAuthenticationRequestSpec extends GovSsoSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Feature("OIDC_REQUEST")
    def "Start SSO authentication request with correct parameters"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        Response response = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        assertEquals(302, response.statusCode(), "Correct HTTP status code is returned")
        assertTrue(response.getHeader("location").startsWith(flow.sessionService.baseUrl))
        assertTrue(response.getHeader("location").endsWith(flow.getLoginChallenge()))
    }

    @Feature("OIDC_REQUEST")
    def "Start SSO authentication with invalid parameter: #paramKey"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.put(paramKey, paramValue)
        Response response = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        assertEquals(302, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals(error, Utils.getParamValueFromResponseHeader(response, "error"), "Error parameter exists")
        assertEquals( errorMessage, Utils.getParamValueFromResponseHeader(response, "error_description"), "Correct error message is returned")

        where:
        paramKey            | paramValue | error                       | errorMessage
        "scope"             | "invalid"  | "invalid_scope"             | "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'invalid'."
        "state"             | "invalid"  | "invalid_state"             | "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy."
        "response_type"     | "token"    | "unsupported_response_type" | "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'token'."
        "response_type"     | "invalid"  | "unsupported_response_type" | "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'invalid'."
        "client_id"         | "invalid"  | "invalid_client"            | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist."
        "redirect_uri"      | "invalid"  | "invalid_request"           | "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls."
    }

    @Feature("OIDC_REQUEST")
    def "Start SSO authentication with missing parameter: #missingParam"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.remove(missingParam)
        Response response = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        assertEquals(302, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals(error, Utils.getParamValueFromResponseHeader(response, "error"), "Error parameter exists")
        assertEquals(errorMessage, Utils.getParamValueFromResponseHeader(response, "error_description"), "Correct error message is returned")

        where:
        missingParam    | error                       | errorMessage
        "state"         | "invalid_state"             | "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy."
        "response_type" | "unsupported_response_type" | "The authorization server does not support obtaining a token using this method. `The request is missing the 'response_type' parameter."
        "client_id"     | "invalid_client"            | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist."
//        "scope"         | "invalid_scope"             | "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'invalid'."
//        "redirect_uri"  | "invalid_request"           | "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls."
    }

    @Ignore("Waiting for ui_locales support")
    @Feature("OIDC_REQUEST")
    def "Authentication request with different ui_locales: #label"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        def value = Utils.setParameter(paramsMap, paramName, paramValue)
        Response initSsoOidcServiceSession = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, initSsoOidcServiceSession)
        Response taraOidcResponse = Steps.followRedirect(flow, sessionServiceRedirectToTaraResponse)
        Response taraLoginResponse = Steps.followRedirect(flow, taraOidcResponse)
        assertEquals(200, taraLoginResponse.statusCode(), "Correct HTTP status code is returned")
        taraLoginResponse.then().body("html.head.title", equalTo(expectedValue))

        where:
        paramName    | paramValue | label                                     || expectedValue
        "ui_locales" | "zu"       | "Fallback into default language et"       || "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        "ui_locales" | "et"       | "Estonian"                                || "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        "ui_locales" | "ru"       | "Russian"                                 || "Национальный сервис аутентификации - Для безопасной аутентификации в э-услугах"
        "ui_locales" | "en"       | "English"                                 || "National authentication service - Secure authentication for e-services"
        "ui_locales" | "fi ru en" | "Select first supported locale from list" || "Национальный сервис аутентификации - Для безопасной аутентификации в э-услугах"
        "ui_locales" | "ET"       | "Estonian with big letters"               || "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        "ui_locales" | "RU"       | "Russian with big letters"                || "Национальный сервис аутентификации - Для безопасной аутентификации в э-услугах"
        "ui_locales" | "EN"       | "English with big letters"                || "National authentication service - Secure authentication for e-services"
        "ui_locales" | _          | "Without locale parameter"                || "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
    }

    @Ignore
    @Feature("OIDC_REQUEST")
    def "Authentication request with unknown parameter"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        def value = paramsMap.put("my_parameter", "654321")
        Response initOIDCServiceSession = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        assertEquals(302, initOIDCServiceSession.statusCode(), "Correct HTTP status code is returned")
        assertThat(initOIDCServiceSession.getHeader("location"), Matchers.containsString("?login_challenge="))
    }

    @Ignore
    @Feature("OIDC_REQUEST")
    def "Authentication request with invalid acr_values parameter value"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        def value = paramsMap.put("acr_values", "medium")
        Response initOIDCServiceSession = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response response = Steps.followRedirect(flow, initOIDCServiceSession)
        assertEquals(500, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertThat(response.body().jsonPath().get("message").toString(), startsWith("Autentimine ebaõnnestus teenuse tehnilise vea tõttu."))
    }
}