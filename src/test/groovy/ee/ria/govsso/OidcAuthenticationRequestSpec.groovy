package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Ignore
import spock.lang.Unroll

import static org.hamcrest.Matchers.allOf
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.equalTo
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

    @Unroll
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
        "prompt"            | "none"     | "login_required"            | "The Authorization Server requires End-User authentication. Prompt 'none' was requested, but no existing login session was found."
        "scope"             | "invalid"  | "invalid_scope"             | "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'invalid'."
        "state"             | "invalid"  | "invalid_state"             | "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy."
        "response_type"     | "token"    | "unsupported_response_type" | "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'token'."
        "response_type"     | "invalid"  | "unsupported_response_type" | "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'invalid'."
        "client_id"         | "invalid"  | "invalid_client"            | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist."
        "redirect_uri"      | "invalid"  | "invalid_request"           | "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls."
    }

    @Unroll
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

    @Feature("OIDC_REQUEST")
    def "Authentication request with unknown parameter"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        def value = paramsMap.put("my_parameter", "654321")
        Response initOIDCServiceSession = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        assertEquals(302, initOIDCServiceSession.statusCode(), "Correct HTTP status code is returned")
        assertThat(initOIDCServiceSession.getHeader("location"), containsString("?login_challenge="))
    }

    @Unroll
    @Feature("SECURE_COOKIE_HANDLING")
    def "Correct set-cookie parameters in responses"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)
        Response callbackResponse = Steps.followRedirectWithCookies(flow, taraAuthentication, flow.sessionService.cookies)
        Response loginVerifierResponse = Steps.followRedirectWithCookies(flow, callbackResponse, flow.ssoOidcService.cookies)

        assertThat("Correct cookie attributes", oidcServiceInitResponse.getDetailedCookie("oauth2_authentication_csrf").toString(), allOf(containsString("Path=/"), containsString("HttpOnly"), containsString("SameSite=None"), containsString("Secure")))
        assertThat("Correct cookie attributes", loginVerifierResponse.getDetailedCookie("oauth2_authentication_session").toString(), allOf(containsString("Path=/"), containsString("HttpOnly"), containsString("SameSite=None"), containsString("Secure"), containsString("Max-Age=900")))
        assertThat("Correct cookie attributes", loginVerifierResponse.getDetailedCookie("oauth2_consent_csrf").toString(), allOf(containsString("Path=/"), containsString("HttpOnly"), containsString("SameSite=None"), containsString("Secure")))
    }

    @Unroll
    @Feature("OIDC_REQUEST")
    def "Incorrect OIDC login verifier request: #reason"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)
        Response callbackResponse = Steps.followRedirectWithCookies(flow, taraAuthentication, flow.sessionService.cookies)

        HashMap<String, String> queryParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(queryParams, "client_id", Utils.getParamValueFromResponseHeader(callbackResponse, clientId))
        Utils.setParameter(queryParams, "login_verifier", Utils.getParamValueFromResponseHeader(callbackResponse, loginVerifier))
        Utils.setParameter(queryParams, "redirect_uri", Utils.getParamValueFromResponseHeader(callbackResponse, redirectUri))
        Utils.setParameter(queryParams, "response_type", Utils.getParamValueFromResponseHeader(callbackResponse, responseType))
        Utils.setParameter(queryParams, "scope", Utils.getParamValueFromResponseHeader(callbackResponse, scope))
        Utils.setParameter(queryParams, "state", Utils.getParamValueFromResponseHeader(callbackResponse, state))

        Response oidcServiceAuthResponse = Requests.getRequestWithCookiesAndParams(flow, flow.ssoOidcService.fullAuthenticationRequestUrl, flow.ssoOidcService.cookies, queryParams, Collections.emptyMap())

        assertEquals(302, oidcServiceAuthResponse.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals(error, Utils.getParamValueFromResponseHeader(oidcServiceAuthResponse,"error_description"), "Correct HTTP status code is returned")

        where:
        reason                    | clientId    | loginVerifier    | redirectUri    | responseType    | scope       | state   | error
        "Incorrect client_id"     | "scope"     | "login_verifier" | "redirect_uri" | "response_type" | "scope"     | "state" | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist."
        "Incorrect login_verifier"| "client_id" | "scope"          | "redirect_uri" | "response_type" | "scope"     | "state" | "The resource owner or authorization server denied the request. The login verifier has already been used, has not been granted, or is invalid."
        "Incorrect redirect_uri"  | "client_id" | "login_verifier" | "scope"        | "response_type" | "scope"     | "state" | "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls."
        "Incorrect response_type" | "client_id" | "login_verifier" | "redirect_uri" | "scope"         | "scope"     | "state" | "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'openid'."
        "Incorrect scope"         | "client_id" | "login_verifier" | "redirect_uri" | "response_type" | "client_id" | "state" | "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'client-a'."
        "Incorrect state"         | "client_id" | "login_verifier" | "redirect_uri" | "response_type" | "scope"     | "scope" | "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy."
    }

    @Unroll
    @Feature("OIDC_REQUEST")
    def "Incorrect OIDC consent verifier request: #reason"() {
        expect:
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)
        Response callbackResponse = Steps.followRedirectWithCookies(flow, taraAuthentication, flow.sessionService.cookies)
        Response loginVerifierResponse = Steps.followRedirectWithCookies(flow, callbackResponse, flow.ssoOidcService.cookies)
        Response consentResponse = Steps.followRedirectWithCookies(flow, loginVerifierResponse, flow.ssoOidcService.cookies)

        HashMap<String, String> queryParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(queryParams, "client_id", Utils.getParamValueFromResponseHeader(consentResponse, clientId))
        Utils.setParameter(queryParams, "consent_verifier", Utils.getParamValueFromResponseHeader(consentResponse, consentVerifier))
        Utils.setParameter(queryParams, "redirect_uri", Utils.getParamValueFromResponseHeader(consentResponse, redirectUri))
        Utils.setParameter(queryParams, "response_type", Utils.getParamValueFromResponseHeader(consentResponse, responseType))
        Utils.setParameter(queryParams, "scope", Utils.getParamValueFromResponseHeader(consentResponse, scope))
        Utils.setParameter(queryParams, "state", Utils.getParamValueFromResponseHeader(consentResponse, state))

        Response oidcServiceAuthResponse = Requests.getRequestWithCookiesAndParams(flow, flow.ssoOidcService.fullAuthenticationRequestUrl, flow.ssoOidcService.cookies, queryParams, Collections.emptyMap())

        assertEquals(302, oidcServiceAuthResponse.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals(error, Utils.getParamValueFromResponseHeader(oidcServiceAuthResponse,"error_description"), "Correct HTTP status code is returned")

        where:
        reason                       | clientId    | consentVerifier    | redirectUri    | responseType    | scope       | state   | error
        "Incorrect client_id"        | "scope"     | "consent_verifier" | "redirect_uri" | "response_type" | "scope"     | "state" | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist."
        "Incorrect consent_verifier" | "client_id" | "scope"            | "redirect_uri" | "response_type" | "scope"     | "state" | "The resource owner or authorization server denied the request. The consent verifier has already been used, has not been granted, or is invalid."
        "Incorrect redirect_uri"     | "client_id" | "consent_verifier" | "scope"        | "response_type" | "scope"     | "state" | "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls."
        "Incorrect responseType"     | "client_id" | "consent_verifier" | "redirect_uri" | "scope"         | "scope"     | "state" | "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'openid'."
        "Incorrect scope"            | "client_id" | "consent_verifier" | "redirect_uri" | "response_type" | "client_id" | "state" | "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'client-a'."
        "Incorrect state"            | "client_id" | "consent_verifier" | "redirect_uri" | "response_type" | "scope"     | "scope" | "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy."
    }

    @Feature("OIDC_REQUEST")
    @Feature("LOGOUT")
    def "Start logout request with correct parameters"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovsso(flow)
        Response initLogout = Steps.startLogout(flow, createSession.jsonPath().get("id_token"), flow.oidcClientA.fullBaseUrl)

        assertEquals(302, initLogout.getStatusCode(), "Correct status code")
        assertThat(initLogout.getHeader("location"), containsString("/logout/init?logout_challenge="))
    }

    @Feature("OIDC_REQUEST")
    @Feature("LOGOUT")
    def "Start logout request with not registered logout_redirect_uri"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovsso(flow)
        Response initLogout = Steps.startLogout(flow, createSession.jsonPath().get("id_token"), "https://not.whitelisted.eu")

        String errorDescription = "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. " +
                                  "Logout failed because query parameter post_logout_redirect_uri is not a whitelisted as a post_logout_redirect_uri for the client."

        assertEquals(302, initLogout.getStatusCode(), "Correct status code")
        assertEquals("invalid_request", Utils.getParamValueFromResponseHeader(initLogout, "error"), "Correct error")
        assertEquals(errorDescription, Utils.getParamValueFromResponseHeader(initLogout, "error_description"), "Correct error description")
    }

    @Feature("OIDC_REQUEST")
    @Feature("LOGOUT")
    def "Logout request for client-B with id_token_hint from client-A"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovsso(flow)
        String idToken = createSession.jsonPath().get("id_token")

        Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)

        HashMap<String, String> queryParams = new HashMap<>()
        Utils.setParameter(queryParams, "id_token_hint", idToken)
        Utils.setParameter(queryParams, "post_logout_redirect_uri", flow.oidcClientB.fullBaseUrl)
        Response initLogout = Requests.getRequestWithParams(flow, flow.ssoOidcService.fullLogoutUrl, queryParams, Collections.emptyMap())

        String errorDescription = "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. " +
                "Logout failed because query parameter post_logout_redirect_uri is not a whitelisted as a post_logout_redirect_uri for the client."

        assertEquals(302, initLogout.getStatusCode(), "Correct status code")
        assertEquals("invalid_request", Utils.getParamValueFromResponseHeader(initLogout,"error"), "Correct error")
        assertEquals(errorDescription, Utils.getParamValueFromResponseHeader(initLogout,"error_description"), "Correct error description")
    }

    @Feature("LOGOUT")
    def "Logout request with incorrect logout_verifier parameter"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)

        Response continueWithExistingSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueWithExistingSession.jsonPath().get("id_token")

        Steps.logout(flow, idToken, flow.oidcClientB.fullBaseUrl, flow.sessionService.fullLogoutEndSessionUrl)

        HashMap<String, String> queryParams = new HashMap<>()
        Utils.setParameter(queryParams, "logout_verifier", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

        Response logoutVerifier = Requests.getRequestWithParams(flow, flow.ssoOidcService.fullLogoutUrl,  queryParams, Collections.emptyMap())

        assertEquals(302, logoutVerifier.getStatusCode(), "Correct status code")
        assertEquals("Not Found", Utils.getParamValueFromResponseHeader(logoutVerifier,"error"), "Correct error")
        assertEquals("Unable to locate the requested resource", Utils.getParamValueFromResponseHeader(logoutVerifier,"error_description"), "Correct error description")
    }
}