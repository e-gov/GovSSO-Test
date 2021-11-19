package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import org.hamcrest.Matchers
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Ignore

import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.startsWith
import static org.junit.jupiter.api.Assertions.*
import static org.hamcrest.MatcherAssert.assertThat

//TODO: Transferred tests from TARA2 project for preliminary usage
class OidcAuthenticationRequestSpec extends GovSsoSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Feature("")
    def "Start SSO authentication request with correct parameters"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        Response response = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        assertEquals(302, response.statusCode(), "Correct HTTP status code is returned")
        assertTrue(response.getHeader("location").startsWith(flow.sessionService.baseUrl))
        assertTrue(response.getHeader("location").endsWith(flow.getLoginChallenge()))
    }
    @Ignore
    @Feature("")
    def "Start SSO authentication with invalid parameter: #paramKey"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.put(paramKey, paramValue)
        Response response = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        assertEquals(302, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals(error, Utils.getParamValueFromResponseHeader(response, "error"), "Error parameter exists")
        assertTrue(Utils.getParamValueFromResponseHeader(response, "error_description").matches(errorMessage), "Correct error message is returned")

        where:
        paramKey            | paramValue | error                       | errorMessage
        "scope"             | "invalid"  | "invalid_scope"             | "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'invalid'."
        "state"             | "invalid"  | "invalid_state"             | "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy."
        "response_type"     | "token"    | "unsupported_response_type" | "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'token'."
        "response_type"     | "invalid"  | "unsupported_response_type" | "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'invalid'."
        "client_id"         | "invalid"  | "invalid_client"            | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist."
        "redirect_uri"      | "invalid"  | "invalid_request"           | "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls."
        "additional_param"  | "invalid"  | "invalid_request"           | ""
    }

    @Ignore
    @Feature("")
    def "Start SSO authentication with missing parameter: #missingParam"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.remove(missingParam)
        Response response = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        assertEquals(302, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals(error, Utils.getParamValueFromResponseHeader(response, "error"), "Error parameter exists")
        assertTrue(Utils.getParamValueFromResponseHeader(response, "error_description").matches(errorMessage), "Correct error message is returned")

        where:
        missingParam    | error                       | errorMessage
        "scope"         | "invalid_scope"             | "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'invalid'."
        "state"         | "invalid_state"             | "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy."
        "response_type" | "unsupported_response_type" | "The authorization server does not support obtaining a token using this method. `The request is missing the 'response_type' parameter."
        "client_id"     | "invalid_client"            | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist."
        "redirect_uri"  | "invalid_request"           | "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls."
    }

    @Ignore("Waiting for development")
    @Feature("")
    def "Authentication request with different ui_locales: #label"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        def value = Utils.setParameter(paramsMap, paramName, paramValue)
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        Response response = Steps.followRedirect(flow, initOIDCServiceSession)
        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        response.then().body("html.head.title", equalTo(expectedValue))

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
    @Feature("")
    def "Authentication request with unknown parameter"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        def value = paramsMap.put("my_parameter", "654321")
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        assertEquals(302, initOIDCServiceSession.statusCode(), "Correct HTTP status code is returned")
        assertThat(initOIDCServiceSession.getHeader("location"), Matchers.containsString("?login_challenge="))
    }
    @Ignore
    @Feature("")
    def "Authentication request with invalid acr_values parameter value"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        def value = paramsMap.put("acr_values", "medium")
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        Response response = Steps.followRedirect(flow, initOIDCServiceSession)
        assertEquals(500, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertThat(response.body().jsonPath().get("message").toString(), startsWith("Autentimine ebaõnnestus teenuse tehnilise vea tõttu."))
    }

    @Ignore
    @Feature("")
    def "Authentication request with empty scope"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "")
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        Response response = Steps.followRedirect(flow, initOIDCServiceSession)
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertThat(response.body().jsonPath().get("message").toString(), startsWith("Päringus puudub scope parameeter."))
    }
    @Ignore
    @Feature("")
    def "Authentication request with empty optional parameters: #paramName"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "openid")
        def value = Utils.setParameter(paramsMap, paramName, paramValue)
        if (paramName.equalsIgnoreCase("nonce")) {
            flow.setNonce("")
        }
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        Steps.createLoginSession(flow, initOIDCServiceSession)

        String certificate = Utils.getCertificateAsString("src/test/resources/joeorg-auth.pem")
        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(headersMap, "XCLIENTCERTIFICATE", certificate)
        Requests.idCardAuthentication(flow, headersMap)
        Response acceptResponse = Requests.acceptAuthTara(flow, flow.taraLoginService.fullAuthAcceptUrl)
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)

        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)

        if (consentResponse.getStatusCode() == 200) {
            consentResponse = Steps.submitConsent(flow, true)
            assertEquals(302, consentResponse.statusCode(), "Correct HTTP status code is returned")
            Steps.verifyResponseHeaders(consentResponse)
        }
        Response oidcserviceResponse = Steps.followRedirectWithCookies(flow, consentResponse, flow.oidcService.cookies)
        Response sa = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        String authorizationCode = Utils.getParamValueFromResponseHeader(oidcserviceResponse, "code")
        Response tokenResponse = Requests.getWebToken(flow, authorizationCode)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClient.clientId))
        assertThat(claims.getSubject(), equalTo("EE38001085718"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("JAAK-KRISTJAN"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("family_name"), equalTo("JÕEORG"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("date_of_birth"), equalTo("1980-01-08"))
        assertThat(claims.getClaim("amr")[0].toString(), equalTo("idcard"))
        assertThat(claims.getClaim("acr"), equalTo("high"))

        where:
        paramName    | paramValue
        "ui_locales" | _
        "nonce" | _
        "acr_values" | _
        "redirect_uri" | _
    }
    @Ignore
    @Feature("")
    def "Authentication request with empty mandatory parameters: #paramName"() {
        expect:

        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "openid")
        def value = Utils.setParameter(paramsMap, paramName, paramValue)

        Response response = Requests.getRequestWithParams(flow, flow.oidcService.fullAuthenticationRequestUrl, value,  Collections.emptyMap())
        assertEquals(expectedErrorDescription ,Utils.getParamValueFromResponseHeader(response, "error_description"), "Error description parameter exists")

        where:
        paramName    | paramValue | expectedErrorDescription
        "state" | _ | "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy."
        "response_type" | _ | "The authorization server does not support obtaining a token using this method. `The request is missing the 'response_type' parameter."
        "client_id" | _ | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist."
    }
}