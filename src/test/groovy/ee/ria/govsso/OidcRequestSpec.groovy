package ee.ria.govsso

import com.google.common.hash.Hashing
import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll
import java.nio.charset.StandardCharsets

import static org.hamcrest.Matchers.*
import static org.hamcrest.MatcherAssert.assertThat

class OidcRequestSpec extends GovSsoSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Feature("OIDC_ENDPOINT")
    def "Start SSO authentication request with correct parameters"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        assertThat("Correct HTTP status code", oidcAuth.statusCode(), is(302))
        assertThat("Correct location", oidcAuth.getHeader("location").startsWith(flow.sessionService.baseUrl))
        assertThat("Correct location", oidcAuth.getHeader("location").endsWith(flow.getLoginChallenge()))
    }

    @Feature("OIDC_ENDPOINT")
    def "Authentication request with incorrect client ID"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "invalid-client-id", flow.oidcClientA.fullResponseUrl)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response oidcError = Steps.followRedirect(flow, oidcAuth)

        assertThat("Correct HTTP status code", oidcError.statusCode(), is(400))
        assertThat("Correct path", oidcError.jsonPath().getString("path"), is("/error/oidc"))
        assertThat("Correct error", oidcError.jsonPath().getString("error"), is("USER_INVALID_OIDC_CLIENT"))
        assertThat("Correct message", oidcError.jsonPath().getString("message"), is("Vale <span translate=\"no\">OIDC</span> klient."))
        assertThat("Contains incident number", oidcError.jsonPath().getString("incident_nr").size()==32)
    }

    @Unroll
    @Feature("OIDC_ENDPOINT")
    def "Start OIDC authentication with invalid parameter: #paramKey"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.put(paramKey, paramValue)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        assertThat("Correct HTTP status code", oidcAuth.statusCode(), is(statusCode))
        assertThat("Correct error parameter", Utils.getParamValueFromResponseHeader(oidcAuth, "error"), is(error))
        assertThat("Correct error message", Utils.getParamValueFromResponseHeader(oidcAuth, "error_description"), is(errorMessage))

        where:
        paramKey        | paramValue | error                       | statusCode | errorMessage
        "prompt"        | "none"     | "login_required"            | 303        | "The Authorization Server requires End-User authentication. Prompt 'none' was requested, but no existing login session was found."
        "scope"         | "invalid"  | "invalid_scope"             | 303        | "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'invalid'."
        "state"         | "invalid"  | "invalid_state"             | 303        | "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy."
        "response_type" | "token"    | "unsupported_response_type" | 303        | "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'token'."
        "response_type" | "invalid"  | "unsupported_response_type" | 303        | "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'invalid'."
        "client_id"     | "invalid"  | "invalid_client"            | 302        | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist."
        "redirect_uri"  | "invalid"  | "invalid_request"           | 302        | "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls."
    }

    @Unroll
    @Feature("OIDC_ENDPOINT")
    def "Start SSO authentication with missing parameter: #missingParam"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.remove(missingParam)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        assertThat("Correct HTTP status code", oidcAuth.statusCode(), is(statusCode))
        assertThat("Correct error parameter", Utils.getParamValueFromResponseHeader(oidcAuth, "error"), is(error))
        assertThat("Correct error message", Utils.getParamValueFromResponseHeader(oidcAuth, "error_description"), is(errorMessage))

        where:
        missingParam    | error                       | statusCode | errorMessage
        "state"         | "invalid_state"             | 303        | "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy."
        "response_type" | "unsupported_response_type" | 303        | "The authorization server does not support obtaining a token using this method. `The request is missing the 'response_type' parameter."
        "client_id"     | "invalid_client"            | 302        | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist."
    }

    @Feature("OIDC_ENDPOINT")
    def "Authentication request with different ui_locales: #label"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.put("ui_locales", uiLocales)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraOidcAuth = Steps.followRedirect(flow, initLogin)
        Response taraInitLogin = Steps.followRedirect(flow, taraOidcAuth)

        assertThat("Correct HTTP status code", taraInitLogin.statusCode(), is(200))
        taraInitLogin.then().body("html.head.title", equalTo(expectedValue))

        where:
        uiLocales | label                                     | expectedValue
        "zu"       | "Fallback into default language et"       | "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        "et"       | "Estonian"                                | "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        "ru"       | "Russian"                                 | "Государственная услуга аутентификации - Для безопасной аутентификации в э-услугах"
        "en"       | "English"                                 | "State authentication service - Secure authentication for e-services"
        "fi ru en" | "Select first supported locale from list" | "Государственная услуга аутентификации - Для безопасной аутентификации в э-услугах"
        "ET"       | "Estonian with capital letters"           | "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        "RU"       | "Russian with capital letters"            | "Государственная услуга аутентификации - Для безопасной аутентификации в э-услугах"
        "EN"       | "English with capital letters"            | "State authentication service - Secure authentication for e-services"
        null       | "Without locale parameter"                | "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
    }

    @Feature("OIDC_ENDPOINT")
    def "Authentication request with unknown parameter"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        def value = paramsMap.put("my_parameter", "654321")
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        assertThat("Correct HTTP status code", oidcAuth.statusCode(), is(302))
        assertThat("Correct location", oidcAuth.getHeader("location").startsWith(flow.sessionService.baseUrl))
        assertThat("Correct location", oidcAuth.getHeader("location").endsWith(flow.getLoginChallenge()))
    }

    @Unroll
    @Feature("OIDC_ENDPOINT")
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
    @Feature("OIDC_ENDPOINT")
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

        assertThat("Correct HTTP status code", loginVerifier.getStatusCode(), is(statusCode))
        assertThat("Correct error description", Utils.getParamValueFromResponseHeader(loginVerifier,"error_description"), is(error))

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
    @Feature("OIDC_ENDPOINT")
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

        assertThat("Correct HTTP status code", consentVerifier.getStatusCode(), is(statusCode))
        assertThat("Correct error description", Utils.getParamValueFromResponseHeader(consentVerifier,"error_description"), is(error))

        where:
        reason                       | clientId    | consent_verifier   | redirectUri    | responseType    | scope       | state   | statusCode | error
        "Incorrect client_id"        | "scope"     | "consent_verifier" | "redirect_uri" | "response_type" | "scope"     | "state" | 302        | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist."
        "Incorrect consent_verifier" | "client_id" | "scope"            | "redirect_uri" | "response_type" | "scope"     | "state" | 303        | "The resource owner or authorization server denied the request. The consent verifier has already been used, has not been granted, or is invalid."
        "Incorrect redirect_uri"     | "client_id" | "consent_verifier" | "scope"        | "response_type" | "scope"     | "state" | 302        | "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls."
        "Incorrect responseType"     | "client_id" | "consent_verifier" | "redirect_uri" | "scope"         | "scope"     | "state" | 303        | "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'openid'."
        "Incorrect scope"            | "client_id" | "consent_verifier" | "redirect_uri" | "response_type" | "client_id" | "state" | 303        | "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'client-a'."
        "Incorrect state"            | "client_id" | "consent_verifier" | "redirect_uri" | "response_type" | "scope"     | "scope" | 303        | "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy."
    }

    @Feature("OIDC_LOGOUT_ENDPOINT")
    def "Start logout request with correct parameters"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        Response initLogout = Steps.startLogout(flow, createSession.jsonPath().get("id_token"), flow.oidcClientA.fullLogoutRedirectUrl)

        assertThat("Correct HTTP status code", initLogout.getStatusCode(), is(302))
        assertThat("Correct location", initLogout.getHeader("location").startsWith(flow.sessionService.baseUrl))
        assertThat("Correct location", initLogout.getHeader("location").endsWith(flow.getLogoutChallenge()))
    }

    @Feature("OIDC_LOGOUT_ENDPOINT")
    def "Start logout request with not registered logout_redirect_uri"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        Response initLogout = Steps.startLogout(flow, createSession.jsonPath().get("id_token"), "https://not.whitelisted.eu")

        String errorDescription = "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. " +
                                  "Logout failed because query parameter post_logout_redirect_uri is not a whitelisted as a post_logout_redirect_uri for the client."

        assertThat("Correct HTTP status code", initLogout.getStatusCode(), is(302))
        assertThat("Correct error", Utils.getParamValueFromResponseHeader(initLogout, "error"), is("invalid_request"))
        assertThat("Correct error description", Utils.getParamValueFromResponseHeader(initLogout, "error_description"), is(errorDescription))
    }

    @Feature("OIDC_LOGOUT_ENDPOINT")
    def "Logout request for client-B with id_token_hint from client-A"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        String idToken = createSession.jsonPath().get("id_token")

        Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)

        HashMap<String, String> queryParams = new HashMap<>()
        Utils.setParameter(queryParams, "id_token_hint", idToken)
        Utils.setParameter(queryParams, "post_logout_redirect_uri", flow.oidcClientB.fullBaseUrl)
        Response initLogout = Requests.getRequestWithParams(flow, flow.ssoOidcService.fullLogoutUrl, queryParams, Collections.emptyMap())

        String errorDescription = "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. " +
                "Logout failed because query parameter post_logout_redirect_uri is not a whitelisted as a post_logout_redirect_uri for the client."

        assertThat("Correct HTTP status code", initLogout.getStatusCode(), is(302))
        assertThat("Correct error", Utils.getParamValueFromResponseHeader(initLogout, "error"), is("invalid_request"))
        assertThat("Correct error description", Utils.getParamValueFromResponseHeader(initLogout, "error_description"), is(errorDescription))
    }

    @Feature("OIDC_LOGOUT_ENDPOINT")
    def "Logout request with incorrect logout_verifier parameter"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueSession.jsonPath().get("id_token")

        Steps.logout(flow, idToken, flow.oidcClientB.fullBaseUrl, flow.sessionService.fullLogoutEndSessionUrl)

        HashMap<String, String> queryParams = new HashMap<>()
        Utils.setParameter(queryParams, "logout_verifier", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

        Response logoutVerifier = Requests.getRequestWithParams(flow, flow.ssoOidcService.fullLogoutUrl,  queryParams, Collections.emptyMap())

        assertThat("Correct HTTP status code", logoutVerifier.getStatusCode(), is(302))
        assertThat("Correct error", Utils.getParamValueFromResponseHeader(logoutVerifier, "error"), is("Not Found"))
        assertThat("Correct error description", Utils.getParamValueFromResponseHeader(logoutVerifier, "error_description"), is("Unable to locate the requested resource"))
    }

    @Feature("OIDC_LOGOUT_ENDPOINT")
    def "Correct URL returned from OIDC after return to service provider request"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcAuth)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", flow.getLoginChallenge().toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))
        Response loginReject = Requests.postRequestWithParams(flow, flow.sessionService.fullLoginRejectUrl, formParams)
        Response loginVerifier = Steps.followRedirect(flow, loginReject)

        assertThat("Correct HTTP status code", loginVerifier.getStatusCode(), is(303))
        assertThat("Correct redirect URL", loginVerifier.getHeader("location").startsWith(flow.oidcClientB.fullBaseUrl))
        assertThat("Correct error in URL", loginVerifier.getHeader("location").contains("error=user_cancel"))
        assertThat("Correct error description in URL", loginVerifier.getHeader("location").contains("error_description=User+canceled+the+authentication+process."))
        assertThat("URL contains state parameter", loginVerifier.getHeader("location").contains("state"))
    }

    @Feature("OIDC_ENDPOINT")
    def "Incorrect govsso_login_challenge passed to TARA: #govSsoLoginChallenge"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)

        Map<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "govsso_login_challenge", govSsoLoginChallenge)

        Response taraOidcAuth = Steps.followRedirectWithAlteredQueryParameters(flow, initLogin, paramsMap)
        Response taraInitLogin = Steps.followRedirect(flow, taraOidcAuth)

        assertThat("Correct HTTP status code", taraInitLogin.getStatusCode(), is(400))
        assertThat("Correct error", taraInitLogin.jsonPath().getString("error"), is("Bad Request"))
        assertThat("Correct error message", taraInitLogin.jsonPath().getString("message"), is("Vigane päring. GovSSO päringu volituskood ei ole korrektne."))

        where:
        _ | govSsoLoginChallenge
        _ | "00000000000000000000000000000000"
        _ | ""
    }

    @Feature("OIDC_ENDPOINT")
    def "Start logout with an expired ID token"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)
        Response oidcLogout = Steps.startLogout(flow, flow.oidcClientA.expiredJwt, flow.oidcClientA.fullLogoutRedirectUrl)

        assertThat("Correct HTTP status code", oidcLogout.getStatusCode(), is(302))
        assertThat("Correct redirect location", oidcLogout.getHeader("Location"), startsWith(flow.oidcClientA.fullLogoutRedirectUrl.toString()))
    }

    @Feature("OIDC_ENDPOINT")
    def "Update session after OIDC logout request"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        String idToken = createSession.getBody().jsonPath().get("id_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, flow.oidcClientA.fullLogoutRedirectUrl)

        Response oidcUpdateSession = Steps.updateSessionWithDefaults(flow, idToken)

        Response initLogout = Steps.followRedirect(flow, oidcLogout)
        Response logoutVerifier = Steps.followRedirect(flow, initLogout)

        assertThat("Correct HTTP status code", oidcUpdateSession.getStatusCode(), is(200))
        assertThat("Correct HTTP status code", logoutVerifier.getStatusCode(), is(302))
        assertThat("Correct redirect location", logoutVerifier.getHeader("Location"), startsWith(flow.oidcClientA.fullLogoutRedirectUrl.toString()))
    }

    @Feature("OIDC_ENDPOINT")
    def "Update session after logout init request"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        String idToken = createSession.getBody().jsonPath().get("id_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, flow.oidcClientA.fullLogoutRedirectUrl)
        Response initLogout = Steps.followRedirect(flow, oidcLogout)

        Response oidcUpdateSession = Steps.updateSessionWithDefaults(flow, idToken)

        Response logoutVerifier = Steps.followRedirect(flow, initLogout)

        assertThat("Correct HTTP status code", oidcUpdateSession.getStatusCode(), is(200))
        assertThat("Correct HTTP status code", logoutVerifier.getStatusCode(), is(302))
        assertThat("Correct redirect location", logoutVerifier.getHeader("Location"), startsWith(flow.oidcClientA.fullLogoutRedirectUrl.toString()))
    }

    @Feature("OIDC_ENDPOINT")
    def "Update session after OIDC logout verifier request"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        String idToken = createSession.getBody().jsonPath().get("id_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, flow.oidcClientA.fullLogoutRedirectUrl)
        Response initLogout = Steps.followRedirect(flow, oidcLogout)
        Response logoutVerifier = Steps.followRedirect(flow, initLogout)

        Response oidcUpdateSession = Steps.startSessionUpdateInSsoOidcWithDefaults(flow, idToken, flow.oidcClientA.fullBaseUrl)

        assertThat("Correct HTTP status code", logoutVerifier.getStatusCode(), is(302))
        assertThat("Correct HTTP status code", oidcUpdateSession.getStatusCode(), is(303))
        assertThat("Correct error description in URL", oidcUpdateSession.getHeader("location").contains("error_description=The+Authorization+Server+requires+End-User+authentication.+Prompt+%27none%27+was+requested%2C+but+no+existing+login+session+was+found"))
    }

    @Feature("OIDC_ENDPOINT")
    def "Start session update in client-A after initiating reauthentication with client-B due to acr discrepancy"() {
        expect:
        Response createSession = Steps.authenticateWithEidasInGovSso(flow, "substantial", "C")
        String idToken = createSession.getBody().jsonPath().get("id_token")

        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Steps.followRedirect(flow, oidcAuth)

        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", flow.getLoginChallenge().toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))
        Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullReauthenticateUrl, flow.ssoOidcService.cookies, formParams)

        Response oidcUpdateSession = Steps.startSessionUpdateInSsoOidcWithDefaults(flow, idToken, flow.oidcClientA.fullBaseUrl)

        assertThat("Correct HTTP status code", oidcUpdateSession.getStatusCode(), is(303))
        assertThat("Correct redirect URL", oidcUpdateSession.getHeader("location").startsWith(flow.oidcClientA.fullBaseUrl))
        assertThat("Correct error in URL", oidcUpdateSession.getHeader("location").contains("error=login_required"))
        assertThat("Correct error description in URL", oidcUpdateSession.getHeader("location").contains("error_description=The+Authorization+Server+requires+End-User+authentication.+Prompt+%27none%27+was+requested%2C+but+no+existing+login+session+was+found"))
        assertThat("URL contains state parameter", oidcUpdateSession.getHeader("location").contains("state"))
    }
}