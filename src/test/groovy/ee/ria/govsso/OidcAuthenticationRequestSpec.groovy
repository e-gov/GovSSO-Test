package ee.ria.govsso

import com.google.common.hash.Hashing
import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll
import java.nio.charset.StandardCharsets

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
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        assertEquals(302, oidcAuth.statusCode(), "Correct HTTP status code is returned")
        assertTrue(oidcAuth.getHeader("location").startsWith(flow.sessionService.baseUrl))
        assertTrue(oidcAuth.getHeader("location").endsWith(flow.getLoginChallenge()))
    }

    @Feature("OIDC_REQUEST")
    def "Authentication request with incorrect client ID"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "invalid-client-id", flow.oidcClientA.fullResponseUrl)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response oidcError = Steps.followRedirect(flow, oidcAuth)

        assertEquals(400, oidcError.getStatusCode(), "Correct HTTP status code")
        assertEquals("/error/oidc", oidcError.jsonPath().getString("path"), "Correct error")
        assertEquals("USER_INVALID_OIDC_CLIENT", oidcError.jsonPath().getString("error"), "Correct error")
        assertEquals("Vale OIDC klient.", oidcError.jsonPath().getString("message"), "Correct message")
        assertTrue(oidcError.jsonPath().getString("incident_nr").size()==32, "Contains incident number")
    }

    @Unroll
    @Feature("OIDC_REQUEST")
    def "Start OIDC authentication with invalid parameter: #paramKey"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.put(paramKey, paramValue)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        assertEquals(statusCode, oidcAuth.statusCode(), "Correct HTTP status code is returned")
        assertEquals(error, Utils.getParamValueFromResponseHeader(oidcAuth, "error"), "Error parameter exists")
        assertEquals( errorMessage, Utils.getParamValueFromResponseHeader(oidcAuth, "error_description"), "Correct error message is returned")

        where:
        paramKey            | paramValue | error                       | statusCode | errorMessage
        "prompt"            | "none"     | "login_required"            | 303        | "The Authorization Server requires End-User authentication. Prompt 'none' was requested, but no existing login session was found."
        "scope"             | "invalid"  | "invalid_scope"             | 303        | "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'invalid'."
        "state"             | "invalid"  | "invalid_state"             | 303        | "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy."
        "response_type"     | "token"    | "unsupported_response_type" | 303        | "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'token'."
        "response_type"     | "invalid"  | "unsupported_response_type" | 303        | "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'invalid'."
        "client_id"         | "invalid"  | "invalid_client"            | 302        | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist."
        "redirect_uri"      | "invalid"  | "invalid_request"           | 302        | "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls."
    }

    @Unroll
    @Feature("OIDC_REQUEST")
    def "Start SSO authentication with missing parameter: #missingParam"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.remove(missingParam)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        assertEquals(statusCode, oidcAuth.statusCode(), "Correct HTTP status code is returned")
        assertEquals(error, Utils.getParamValueFromResponseHeader(oidcAuth, "error"), "Error parameter exists")
        assertEquals(errorMessage, Utils.getParamValueFromResponseHeader(oidcAuth, "error_description"), "Correct error message is returned")

        where:
        missingParam    | error                       | statusCode | errorMessage
        "state"         | "invalid_state"             | 303        | "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy."
        "response_type" | "unsupported_response_type" | 303        | "The authorization server does not support obtaining a token using this method. `The request is missing the 'response_type' parameter."
        "client_id"     | "invalid_client"            | 302        | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist."
    }

    @Feature("OIDC_LANGUAGE_SELECTION")
    def "Authentication request with different ui_locales: #label"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.put("ui_locales", uiLocales)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraOidcAuth = Steps.followRedirect(flow, initLogin)
        Response tarainitLogin = Steps.followRedirect(flow, taraOidcAuth)
        assertEquals(200, tarainitLogin.statusCode(), "Correct HTTP status code is returned")
        tarainitLogin.then().body("html.head.title", equalTo(expectedValue))

        where:
        uiLocales | label                                     | expectedValue
        "zu"       | "Fallback into default language et"       | "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        "et"       | "Estonian"                                | "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        "ru"       | "Russian"                                 | "Национальный сервис аутентификации - Для безопасной аутентификации в э-услугах"
        "en"       | "English"                                 | "National authentication service - Secure authentication for e-services"
        "fi ru en" | "Select first supported locale from list" | "Национальный сервис аутентификации - Для безопасной аутентификации в э-услугах"
        "ET"       | "Estonian with capital letters"           | "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        "RU"       | "Russian with capital letters"            | "Национальный сервис аутентификации - Для безопасной аутентификации в э-услугах"
        "EN"       | "English with capital letters"            | "National authentication service - Secure authentication for e-services"
        null       | "Without locale parameter"                | "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
    }

    @Feature("OIDC_REQUEST")
    def "Authentication request with unknown parameter"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        def value = paramsMap.put("my_parameter", "654321")
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        assertEquals(302, oidcAuth.statusCode(), "Correct HTTP status code is returned")
        assertThat(oidcAuth.getHeader("location"), containsString("?login_challenge="))
    }

    @Unroll
    @Feature("SECURE_COOKIE_HANDLING")
    def "Correct set-cookie parameters in responses"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response taracallback = Steps.followRedirectWithCookies(flow, taraAuthentication, flow.sessionService.cookies)
        Response loginVerifier = Steps.followRedirectWithCookies(flow, taracallback, flow.ssoOidcService.cookies)

        assertThat("Correct cookie attributes", oidcAuth.getDetailedCookie("oauth2_authentication_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt()).toString(), allOf(containsString("Path=/"), containsString("HttpOnly"), containsString("SameSite=None"), containsString("Secure"), containsString("Max-Age=3600")))
        assertThat("Correct cookie attributes", loginVerifier.getDetailedCookie("oauth2_authentication_session").toString(), allOf(containsString("Path=/"), containsString("HttpOnly"), containsString("SameSite=None"), containsString("Secure"), containsString("Max-Age=900")))
        assertThat("Correct cookie attributes", loginVerifier.getDetailedCookie("oauth2_consent_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt()).toString(), allOf(containsString("Path=/"), containsString("HttpOnly"), containsString("SameSite=None"), containsString("Secure"), containsString("Max-Age=3600")))
    }

    @Unroll
    @Feature("OIDC_REQUEST")
    def "Incorrect OIDC login verifier request: #reason"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response taracallback = Steps.followRedirectWithCookies(flow, taraAuthentication, flow.sessionService.cookies)

        HashMap<String, String> queryParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(queryParams, "client_id", Utils.getParamValueFromResponseHeader(taracallback, clientId))
        Utils.setParameter(queryParams, "login_verifier", Utils.getParamValueFromResponseHeader(taracallback, login_verifier))
        Utils.setParameter(queryParams, "redirect_uri", Utils.getParamValueFromResponseHeader(taracallback, redirectUri))
        Utils.setParameter(queryParams, "response_type", Utils.getParamValueFromResponseHeader(taracallback, responseType))
        Utils.setParameter(queryParams, "scope", Utils.getParamValueFromResponseHeader(taracallback, scope))
        Utils.setParameter(queryParams, "state", Utils.getParamValueFromResponseHeader(taracallback, state))

        Response loginVerifier = Requests.getRequestWithCookiesAndParams(flow, flow.ssoOidcService.fullAuthenticationRequestUrl, flow.ssoOidcService.cookies, queryParams, Collections.emptyMap())

        assertEquals(statusCode, loginVerifier.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals(error, Utils.getParamValueFromResponseHeader(loginVerifier,"error_description"), "Correct HTTP status code is returned")

        where:
        reason                    | clientId    | login_verifier    | redirectUri    | responseType    | scope       | state   | statusCode | error
        "Incorrect client_id"     | "scope"     | "login_verifier" | "redirect_uri" | "response_type" | "scope"     | "state" | 302        | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist."
        "Incorrect login_verifier"| "client_id" | "scope"          | "redirect_uri" | "response_type" | "scope"     | "state" | 303        | "The resource owner or authorization server denied the request. The login verifier has already been used, has not been granted, or is invalid."
        "Incorrect redirect_uri"  | "client_id" | "login_verifier" | "scope"        | "response_type" | "scope"     | "state" | 302        | "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls."
        "Incorrect response_type" | "client_id" | "login_verifier" | "redirect_uri" | "scope"         | "scope"     | "state" | 303        | "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'openid'."
        "Incorrect scope"         | "client_id" | "login_verifier" | "redirect_uri" | "response_type" | "client_id" | "state" | 303        | "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'client-a'."
        "Incorrect state"         | "client_id" | "login_verifier" | "redirect_uri" | "response_type" | "scope"     | "scope" | 303        | "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy."
    }

    @Unroll
    @Feature("OIDC_REQUEST")
    def "Incorrect OIDC consent verifier request: #reason"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response taracallback = Steps.followRedirectWithCookies(flow, taraAuthentication, flow.sessionService.cookies)
        Response loginVerifier = Steps.followRedirectWithCookies(flow, taracallback, flow.ssoOidcService.cookies)
        Response initConsent = Steps.followRedirectWithCookies(flow, loginVerifier, flow.ssoOidcService.cookies)

        HashMap<String, String> queryParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(queryParams, "client_id", Utils.getParamValueFromResponseHeader(initConsent, clientId))
        Utils.setParameter(queryParams, "consent_verifier", Utils.getParamValueFromResponseHeader(initConsent, consent_verifier))
        Utils.setParameter(queryParams, "redirect_uri", Utils.getParamValueFromResponseHeader(initConsent, redirectUri))
        Utils.setParameter(queryParams, "response_type", Utils.getParamValueFromResponseHeader(initConsent, responseType))
        Utils.setParameter(queryParams, "scope", Utils.getParamValueFromResponseHeader(initConsent, scope))
        Utils.setParameter(queryParams, "state", Utils.getParamValueFromResponseHeader(initConsent, state))

        Response consentVerifier = Requests.getRequestWithCookiesAndParams(flow, flow.ssoOidcService.fullAuthenticationRequestUrl, flow.ssoOidcService.cookies, queryParams, Collections.emptyMap())

        assertEquals(statusCode, consentVerifier.getStatusCode(), "Correct HTTP status code is returned")
        assertEquals(error, Utils.getParamValueFromResponseHeader(consentVerifier,"error_description"), "Correct HTTP status code is returned")

        where:
        reason                       | clientId    | consent_verifier    | redirectUri    | responseType    | scope       | state   | statusCode | error
        "Incorrect client_id"        | "scope"     | "consent_verifier" | "redirect_uri" | "response_type" | "scope"     | "state" | 302        | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist."
        "Incorrect consent_verifier" | "client_id" | "scope"            | "redirect_uri" | "response_type" | "scope"     | "state" | 303        | "The resource owner or authorization server denied the request. The consent verifier has already been used, has not been granted, or is invalid."
        "Incorrect redirect_uri"     | "client_id" | "consent_verifier" | "scope"        | "response_type" | "scope"     | "state" | 302        | "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls."
        "Incorrect responseType"     | "client_id" | "consent_verifier" | "redirect_uri" | "scope"         | "scope"     | "state" | 303        | "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'openid'."
        "Incorrect scope"            | "client_id" | "consent_verifier" | "redirect_uri" | "response_type" | "client_id" | "state" | 303        | "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'client-a'."
        "Incorrect state"            | "client_id" | "consent_verifier" | "redirect_uri" | "response_type" | "scope"     | "scope" | 303        | "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy."
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

        Response continueSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueSession.jsonPath().get("id_token")

        Steps.logout(flow, idToken, flow.oidcClientB.fullBaseUrl, flow.sessionService.fullLogoutEndSessionUrl)

        HashMap<String, String> queryParams = new HashMap<>()
        Utils.setParameter(queryParams, "logout_verifier", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

        Response logoutVerifier = Requests.getRequestWithParams(flow, flow.ssoOidcService.fullLogoutUrl,  queryParams, Collections.emptyMap())

        assertEquals(302, logoutVerifier.getStatusCode(), "Correct status code")
        assertEquals("Not Found", Utils.getParamValueFromResponseHeader(logoutVerifier,"error"), "Correct error")
        assertEquals("Unable to locate the requested resource", Utils.getParamValueFromResponseHeader(logoutVerifier,"error_description"), "Correct error description")
    }

    @Feature("OIDC_REQUEST")
    def "Correct URL returned from OIDC after return to service provider request"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcAuth)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", flow.getLoginChallenge().toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))
        Response loginReject = Requests.postRequestWithParams(flow, flow.sessionService.fullLoginRejectUrl, formParams)
        Response loginVerifier = Steps.followRedirect(flow, loginReject)

        assertTrue(loginVerifier.getHeader("location").startsWith(flow.oidcClientB.fullBaseUrl), "Correct redirect URL")
        assertTrue(loginVerifier.getHeader("location").contains("error=user_cancel"), "Correct error in URL")
        assertTrue(loginVerifier.getHeader("location").contains("error_description=User+canceled+the+authentication+process."), "Correct error description in URL")
        assertTrue(loginVerifier.getHeader("location").contains("state"), "URL contains state parameter")
    }
}