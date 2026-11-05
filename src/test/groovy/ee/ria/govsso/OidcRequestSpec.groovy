package ee.ria.govsso

import com.google.common.hash.Hashing
import ee.ria.govsso.configuration.ConfigHolder
import ee.ria.govsso.model.Client
import ee.ria.govsso.model.ErrorMessage
import ee.ria.govsso.model.HydraError
import ee.ria.govsso.util.ErrorValidator
import ee.ria.govsso.util.HydraErrorValidator
import io.qameta.allure.Feature
import io.restassured.response.Response
import spock.lang.Tag
import spock.lang.Unroll
import java.nio.charset.StandardCharsets

import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.allOf
import static org.hamcrest.Matchers.startsWith
import static ee.ria.govsso.util.HydraErrorValidator.HINT_SESSION_EXPIRED
import static ee.ria.govsso.util.HydraErrorValidator.HINT_TOKEN_VALIDATION_FAILED
import static ee.ria.govsso.util.HydraErrorValidator.responseTypeNotAllowed
import static ee.ria.govsso.util.HydraErrorValidator.scopeNotAllowed
import static org.hamcrest.MatcherAssert.assertThat

class OidcRequestSpec extends GovSsoOidcSpecification {

    static final HINT_CLIENT_NOT_FOUND = "The requested OAuth 2.0 Client does not exist."
    static final HINT_REDIRECT_URI_NOT_REGISTERED = "The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls."
    static final HINT_STATE_TOO_SHORT = "Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy."
    static final HINT_POST_LOGOUT_REDIRECT_URI_NOT_REGISTERED = "Logout failed because query parameter post_logout_redirect_uri is not a whitelisted as a post_logout_redirect_uri for the client."

    @Feature("OIDC_ENDPOINT")
    def "Start SSO authentication request with correct parameters"() {
        expect:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        assertThat("Correct HTTP status code", oidcAuth.statusCode, is(302))
        assertThat("Correct location", oidcAuth.header("location").startsWith(flow.sessionService.baseUrl))
        assertThat("Correct location", oidcAuth.header("location").endsWith(flow.loginChallenge))
    }

    @Feature("OIDC_ENDPOINT")
    def "Authentication request with incorrect client ID"() {
        expect:
        Client invalidClient = new Client(clientId: "invalid-client-id", redirectUris: ClientStore.clientA.redirectUris)
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, invalidClient)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response oidcError = Steps.followRedirect(flow, oidcAuth)

        ErrorValidator.validate(oidcError, ErrorMessage.USER_INVALID_OIDC_CLIENT, "/error/oidc")
    }

    @Unroll
    @Feature("OIDC_ENDPOINT")
    def "Start OIDC authentication with invalid parameter: #paramKey"() {
        expect:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap << [(paramKey): paramValue]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        assertThat("Correct HTTP status code", oidcAuth.statusCode, is(statusCode))
        HydraErrorValidator.validateRedirect(oidcAuth, error, hint)

        where:
        paramKey        | paramValue      || statusCode | error                               | hint
        "prompt"        | "none"          || 303        | HydraError.LOGIN_REQUIRED            | "Prompt 'none' was requested, but no existing login session was found."
        "scope"         | "invalid"       || 303        | HydraError.INVALID_SCOPE             | scopeNotAllowed("invalid")
        "scope"         | "auth_handover" || 303        | HydraError.INVALID_SCOPE             | scopeNotAllowed("auth_handover")
        "state"         | "invalid"       || 303        | HydraError.INVALID_STATE             | HINT_STATE_TOO_SHORT
        "response_type" | "token"         || 303        | HydraError.UNSUPPORTED_RESPONSE_TYPE | responseTypeNotAllowed("token")
        "response_type" | "invalid"       || 303        | HydraError.UNSUPPORTED_RESPONSE_TYPE | responseTypeNotAllowed("invalid")
        "client_id"     | "invalid"       || 302        | HydraError.INVALID_CLIENT            | HINT_CLIENT_NOT_FOUND
        "redirect_uri"  | "invalid"       || 302        | HydraError.INVALID_REQUEST           | HINT_REDIRECT_URI_NOT_REGISTERED
    }

    @Unroll
    @Feature("OIDC_ENDPOINT")
    def "Start SSO authentication with missing parameter: #missingParam"() {
        expect:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap.remove(missingParam)
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        assertThat("Correct HTTP status code", oidcAuth.statusCode, is(statusCode))
        HydraErrorValidator.validateRedirect(oidcAuth, error, hint)

        where:
        missingParam    || statusCode | error                               | hint
        "state"         || 303        | HydraError.INVALID_STATE             | HINT_STATE_TOO_SHORT
        "response_type" || 303        | HydraError.UNSUPPORTED_RESPONSE_TYPE | "`The request is missing the 'response_type' parameter."
        "client_id"     || 302        | HydraError.INVALID_CLIENT            | HINT_CLIENT_NOT_FOUND
    }

    @Feature("OIDC_ENDPOINT")
    def "Authentication request with different ui_locales: #label"() {
        expect:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap << [ui_locales: uiLocales]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraOidcAuth = Steps.followRedirect(flow, initLogin)
        Response taraInitLogin = Steps.followRedirect(flow, taraOidcAuth)

        assertThat("Correct HTTP status code", taraInitLogin.statusCode, is(200))
        taraInitLogin.then().body("html.head.title", equalTo(expectedValue))

        where:
        uiLocales  | label                                     | expectedValue
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
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap << [my_parameter: "654321"]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)

        assertThat("Correct HTTP status code", oidcAuth.statusCode, is(302))
        assertThat("Correct location", oidcAuth.header("location").startsWith(flow.sessionService.baseUrl))
        assertThat("Correct location", oidcAuth.header("location").endsWith(flow.loginChallenge))
    }

    @Unroll
    @Feature("OIDC_ENDPOINT")
    @Feature("SECURE_COOKIE_HANDLING")
    def "Correct set-cookie parameters in responses"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response taracallback = Steps.followRedirect(flow, taraAuthentication)
        Response loginVerifier = Steps.followRedirect(flow, taracallback)

        assertThat("Correct cookie attributes", oidcAuth.detailedCookie("__Host-ory_hydra_login_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt()).toString(), allOf(containsString("Path=/"), containsString("HttpOnly"), containsString("SameSite=Lax"), containsString("Secure"), containsString("Max-Age=3600")))
        assertThat("Correct cookie attributes", loginVerifier.detailedCookie("__Host-ory_hydra_session").toString(), allOf(containsString("Path=/"), containsString("HttpOnly"), containsString("SameSite=Lax"), containsString("Secure")))
        assertThat("Correct cookie attributes", loginVerifier.detailedCookie("__Host-ory_hydra_consent_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt()).toString(), allOf(containsString("Path=/"), containsString("HttpOnly"), containsString("SameSite=Lax"), containsString("Secure"), containsString("Max-Age=3600")))
    }

    @Unroll
    @Feature("OIDC_ENDPOINT")
    def "Incorrect OIDC login verifier request: #reason"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response taracallback = Steps.followRedirect(flow, taraAuthentication)

        Map queryParams = [client_id     : Utils.getParamValueFromResponseHeader(taracallback, clientId),
                           login_verifier: Utils.getParamValueFromResponseHeader(taracallback, login_verifier),
                           redirect_uri  : Utils.getParamValueFromResponseHeader(taracallback, redirectUri),
                           response_type : Utils.getParamValueFromResponseHeader(taracallback, responseType),
                           scope         : Utils.getParamValueFromResponseHeader(taracallback, scope),
                           state         : Utils.getParamValueFromResponseHeader(taracallback, state)]

        Response loginVerifier = Requests.getRequestWithParams(flow, flow.ssoOidcService.fullAuthenticationRequestUrl, queryParams)

        assertThat("Correct HTTP status code", loginVerifier.statusCode, is(statusCode))
        HydraErrorValidator.validateRedirect(loginVerifier, error, hint)

        where:
        reason                     | clientId    | login_verifier   | redirectUri    | responseType    | scope       | state   || statusCode | error                               | hint
        "Incorrect client_id"      | "scope"     | "login_verifier" | "redirect_uri" | "response_type" | "scope"     | "state" || 302        | HydraError.INVALID_CLIENT            | HINT_CLIENT_NOT_FOUND
        "Incorrect login_verifier" | "client_id" | "scope"          | "redirect_uri" | "response_type" | "scope"     | "state" || 303        | HydraError.ACCESS_DENIED             | "The login verifier has already been used, has not been granted, or is invalid."
        "Incorrect redirect_uri"   | "client_id" | "login_verifier" | "scope"        | "response_type" | "scope"     | "state" || 302        | HydraError.INVALID_REQUEST           | HINT_REDIRECT_URI_NOT_REGISTERED
        "Incorrect response_type"  | "client_id" | "login_verifier" | "redirect_uri" | "scope"         | "scope"     | "state" || 303        | HydraError.UNSUPPORTED_RESPONSE_TYPE | responseTypeNotAllowed("openid")
        "Incorrect scope"          | "client_id" | "login_verifier" | "redirect_uri" | "response_type" | "client_id" | "state" || 303        | HydraError.INVALID_SCOPE             | scopeNotAllowed("client-a")
        "Incorrect state"          | "client_id" | "login_verifier" | "redirect_uri" | "response_type" | "scope"     | "scope" || 303        | HydraError.INVALID_STATE             | HINT_STATE_TOO_SHORT
    }

    @Unroll
    @Feature("OIDC_ENDPOINT")
    def "Incorrect OIDC consent verifier request: #reason"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response taracallback = Steps.followRedirect(flow, taraAuthentication)
        Response loginVerifier = Steps.followRedirect(flow, taracallback)
        Response initConsent = Steps.followRedirect(flow, loginVerifier)

        Map queryParams = [client_id       : Utils.getParamValueFromResponseHeader(initConsent, clientId),
                           consent_verifier: Utils.getParamValueFromResponseHeader(initConsent, consent_verifier),
                           redirect_uri    : Utils.getParamValueFromResponseHeader(initConsent, redirectUri),
                           response_type   : Utils.getParamValueFromResponseHeader(initConsent, responseType),
                           scope           : Utils.getParamValueFromResponseHeader(initConsent, scope),
                           state           : Utils.getParamValueFromResponseHeader(initConsent, state)]

        Response consentVerifier = Requests.getRequestWithParams(flow, flow.ssoOidcService.fullAuthenticationRequestUrl, queryParams)

        assertThat("Correct HTTP status code", consentVerifier.statusCode, is(statusCode))
        HydraErrorValidator.validateRedirect(consentVerifier, error, hint)

        where:
        reason                       | clientId    | consent_verifier   | redirectUri    | responseType    | scope       | state   || statusCode | error                               | hint
        "Incorrect client_id"        | "scope"     | "consent_verifier" | "redirect_uri" | "response_type" | "scope"     | "state" || 302        | HydraError.INVALID_CLIENT            | HINT_CLIENT_NOT_FOUND
        "Incorrect consent_verifier" | "client_id" | "scope"            | "redirect_uri" | "response_type" | "scope"     | "state" || 303        | HydraError.ACCESS_DENIED             | "The consent verifier has already been used, has not been granted, or is invalid."
        "Incorrect redirect_uri"     | "client_id" | "consent_verifier" | "scope"        | "response_type" | "scope"     | "state" || 302        | HydraError.INVALID_REQUEST           | HINT_REDIRECT_URI_NOT_REGISTERED
        "Incorrect responseType"     | "client_id" | "consent_verifier" | "redirect_uri" | "scope"         | "scope"     | "state" || 303        | HydraError.UNSUPPORTED_RESPONSE_TYPE | responseTypeNotAllowed("openid")
        "Incorrect scope"            | "client_id" | "consent_verifier" | "redirect_uri" | "response_type" | "client_id" | "state" || 303        | HydraError.INVALID_SCOPE             | scopeNotAllowed("client-a")
        "Incorrect state"            | "client_id" | "consent_verifier" | "redirect_uri" | "response_type" | "scope"     | "scope" || 303        | HydraError.INVALID_STATE             | HINT_STATE_TOO_SHORT
    }

    @Feature("OIDC_LOGOUT_ENDPOINT")
    def "Start logout with HTTP #httpRequest request should succeed"() {
        given:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)

        when:
        Response initLogout = Steps.startLogout(flow, createSession.path("id_token"), ClientStore.clientA.postLogoutRedirectUri, usePost)

        then:
        assertThat("Correct HTTP status code", initLogout.statusCode, is(302))
        assertThat("Correct location", initLogout.header("location").startsWith(flow.sessionService.baseUrl))
        assertThat("Correct location", initLogout.header("location").endsWith(flow.logoutChallenge))

        where:
        httpRequest | usePost
        "post"      | true
        "get"       | false
    }

    @Feature("OIDC_LOGOUT_ENDPOINT")
    def "Start logout request with correct parameters"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        Response initLogout = Steps.startLogout(flow, createSession.path("id_token"), ClientStore.clientA.postLogoutRedirectUri)

        assertThat("Correct HTTP status code", initLogout.statusCode, is(302))
        assertThat("Correct location", initLogout.header("location").startsWith(flow.sessionService.baseUrl))
        assertThat("Correct location", initLogout.header("location").endsWith(flow.logoutChallenge))
    }

    @Feature("OIDC_LOGOUT_ENDPOINT")
    def "Start logout request with not registered logout_redirect_uri"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        Response initLogout = Steps.startLogout(flow, createSession.path("id_token"), "https://not.whitelisted.eu")

        assertThat("Correct HTTP status code", initLogout.statusCode, is(302))
        HydraErrorValidator.validateRedirect(initLogout, HydraError.INVALID_REQUEST, HINT_POST_LOGOUT_REDIRECT_URI_NOT_REGISTERED)
    }

    @Feature("OIDC_LOGOUT_ENDPOINT")
    def "Logout request for client-B with id_token_hint from client-A"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        String idToken = createSession.path("id_token")

        Steps.continueWithExistingSession(flow)

        Map queryParams = [id_token_hint           : idToken,
                           post_logout_redirect_uri: ClientStore.clientB.fullBaseUrl]
        Response initLogout = Requests.getRequestWithParams(flow, flow.ssoOidcService.fullLogoutUrl, queryParams)

        assertThat("Correct HTTP status code", initLogout.statusCode, is(302))
        HydraErrorValidator.validateRedirect(initLogout, HydraError.INVALID_REQUEST, HINT_POST_LOGOUT_REDIRECT_URI_NOT_REGISTERED)
    }

    @Feature("OIDC_LOGOUT_ENDPOINT")
    def "Logout request with incorrect logout_verifier parameter"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String idToken = continueSession.path("id_token")

        Steps.logout(flow, idToken, ClientStore.clientB.postLogoutRedirectUri, flow.sessionService.fullLogoutEndSessionUrl)

        Map queryParams = [logout_verifier: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]

        Response logoutVerifier = Requests.getRequestWithParams(flow, flow.ssoOidcService.fullLogoutUrl, queryParams)

        assertThat("Correct HTTP status code", logoutVerifier.statusCode, is(302))
        assertThat("Correct error", Utils.getParamValueFromResponseHeader(logoutVerifier, "error"), is("Not Found"))
        assertThat("Correct error description", Utils.getParamValueFromResponseHeader(logoutVerifier, "error_description"), is("Unable to locate the requested resource"))
    }

    @Feature("OIDC_LOGOUT_ENDPOINT")
    def "Correct URL returned from OIDC after return to service provider request"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, ClientStore.clientB)
        Response initLogin = Steps.followRedirect(flow, oidcAuth)

        Map formParams = [loginChallenge: flow.loginChallenge,
                          _csrf         : initLogin.htmlPath().get("**.find {it.@name == '_csrf'}.@value")]
        Response loginReject = Requests.postRequestWithParams(flow, flow.sessionService.fullLoginRejectUrl, formParams)
        Response loginVerifier = Steps.followRedirect(flow, loginReject)

        assertThat("Correct HTTP status code", loginVerifier.statusCode, is(303))
        assertThat("Correct redirect URL", loginVerifier.header("location").startsWith(ClientStore.clientB.fullBaseUrl))
        HydraErrorValidator.validateRedirect(loginVerifier, HydraError.USER_CANCEL)
        assertThat("URL contains state parameter", loginVerifier.header("location").contains("state"))
    }

    @Feature("OIDC_ENDPOINT")
    def "Incorrect govsso_login_challenge passed to TARA: #govSsoLoginChallenge"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)

        Map paramsMap = [govsso_login_challenge: govSsoLoginChallenge]

        Response taraOidcAuth = Requests.followRedirectWithParams(flow, initLogin.getHeader("Location"), paramsMap)
        Response taraInitLogin = Steps.followRedirect(flow, taraOidcAuth)

        assertThat("Correct HTTP status code", taraInitLogin.statusCode, is(400))
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
        Response oidcLogout = Steps.startLogout(flow, ConfigHolder.testConf.expiredJwt(), ClientStore.clientA.postLogoutRedirectUri)

        assertThat("Correct HTTP status code", oidcLogout.statusCode, is(302))
        assertThat("Correct redirect location", oidcLogout.header("Location"), startsWith(ClientStore.clientA.postLogoutRedirectUri.toString()))
    }

    @Feature("OIDC_ENDPOINT")
    def "Update session after OIDC logout request"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        String idToken = createSession.body.path("id_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, ClientStore.clientA.postLogoutRedirectUri)

        Response oidcUpdateSession = Steps.updateSession(flow)

        Response initLogout = Steps.followRedirect(flow, oidcLogout)
        Response logoutVerifier = Steps.followRedirect(flow, initLogout)

        assertThat("Correct HTTP status code", oidcUpdateSession.statusCode, is(200))
        assertThat("Correct HTTP status code", logoutVerifier.statusCode, is(302))
        assertThat("Correct redirect location", logoutVerifier.header("Location"), startsWith(ClientStore.clientA.postLogoutRedirectUri))
    }

    @Feature("OIDC_ENDPOINT")
    def "Update session after logout init request"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        String idToken = createSession.body.path("id_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, ClientStore.clientA.postLogoutRedirectUri)
        Response initLogout = Steps.followRedirect(flow, oidcLogout)

        Response oidcUpdateSession = Steps.updateSession(flow)

        Response logoutVerifier = Steps.followRedirect(flow, initLogout)

        assertThat("Correct HTTP status code", oidcUpdateSession.statusCode, is(200))
        assertThat("Correct HTTP status code", logoutVerifier.statusCode, is(302))
        assertThat("Correct redirect location", logoutVerifier.header("Location"), startsWith(ClientStore.clientA.postLogoutRedirectUri))
    }

    @Feature("OIDC_ENDPOINT")
    def "Update session after OIDC logout verifier request"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        String idToken = createSession.body.path("id_token")
        String refreshToken = createSession.body.path("refresh_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, ClientStore.clientA.postLogoutRedirectUri)
        Response initLogout = Steps.followRedirect(flow, oidcLogout)
        Response logoutVerifier = Steps.followRedirect(flow, initLogout)

        Response updateResponse = Steps.tryUpdateSession(flow, ClientStore.clientA, [refresh_token: refreshToken])

        assertThat("Correct HTTP status code", logoutVerifier.statusCode, is(302))
        HydraErrorValidator.validate(updateResponse, HydraError.INVALID_REQUEST, HINT_SESSION_EXPIRED)
    }

    @Tag("eidas")
    @Feature("OIDC_ENDPOINT")
    def "Start session update in client-A after initiating reauthentication with client-B due to acr discrepancy"() {
        expect:
        Response createSession = Steps.authenticateWithEidasInGovSso(flow, "substantial", "C")
        String refreshToken = createSession.body.path("refresh_token")

        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, ClientStore.clientB)
        Response initLogin = Steps.followRedirect(flow, oidcAuth)

        Map formParams = [loginChallenge: flow.loginChallenge,
                          _csrf         : initLogin.htmlPath().get("**.find {it.@name == '_csrf'}.@value")]
        Requests.postRequestWithParams(flow, flow.sessionService.fullReauthenticateUrl, formParams)

        Response updateResponse = Steps.tryUpdateSession(flow, ClientStore.clientA, [refresh_token: refreshToken])

        HydraErrorValidator.validate(updateResponse, HydraError.INVALID_GRANT)
    }

    @Feature("ID_TOKEN")
    def "Update session in client-A with refresh token from client-B"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response continueSession = Steps.continueWithExistingSession(flow)
        String refreshToken2 = continueSession.path("refresh_token")

        Response updateResponse = Steps.tryUpdateSession(flow, ClientStore.clientA, [refresh_token: refreshToken2])

        HydraErrorValidator.validate(updateResponse, HydraError.INVALID_GRANT,
                "The OAuth 2.0 Client ID from this request does not match the ID during the initial token issuance.")
    }

    @Feature("ID_TOKEN")
    def "Update session with already used refresh token"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        String refreshToken1 = createSession.path("refresh_token")

        Steps.updateSession(flow)

        Response updateResponse = Steps.tryUpdateSession(flow, ClientStore.clientA, [refresh_token: refreshToken1])

        HydraErrorValidator.validate(updateResponse, HydraError.TOKEN_INACTIVE, HINT_TOKEN_VALIDATION_FAILED)
    }

    @Feature("ID_TOKEN")
    def "Update session with invalid refresh token"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)

        Response updateResponse = Steps.tryUpdateSession(flow, ClientStore.clientA, [refresh_token: "123abc.123abc"])

        HydraErrorValidator.validate(updateResponse, HydraError.INVALID_GRANT)
    }

    @Feature("OIDC_ENDPOINT")
    def "Update session with not supported session update flow with prompt=none"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)

        String idToken = createSession.path("id_token")
        Response oidcUpdateSession = Steps.startSessionUpdateInSsoOidcWithDefaults(flow, idToken, ClientStore.clientA.fullBaseUrl)
        Response initLogin = Steps.followRedirectWithOrigin(flow, oidcUpdateSession, ClientStore.clientA.fullBaseUrl)

        ErrorValidator.validate(initLogin, ErrorMessage.USER_INPUT)
    }

    @Unroll
    @Feature("OIDC_ENDPOINT")
    def "Missing session cookie in login init request in session continuation flow"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, ClientStore.clientB)
        Response initLogin = Requests.getRequest(oidcAuth.then().extract().response().header("location"))

        ErrorValidator.validate(initLogin, ErrorMessage.USER_INPUT, "/login/init")
    }

    @Unroll
    @Feature("OIDC_ENDPOINT")
    def "Incorrect session cookie in login init request in session continuation flow"() {
        expect:
        Steps.authenticateWithIdCardInGovSso(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, ClientStore.clientB)

        Map cookies = ["__Host-ory_hydra_session": "SW5jb3JyZWN0IHNlc3Npb24gY29va2ll"]
        Response initLogin = Steps.followRedirectWithCookies(flow, oidcAuth, cookies)

        ErrorValidator.validate(initLogin, ErrorMessage.USER_INPUT, "/login/init")
    }
}
