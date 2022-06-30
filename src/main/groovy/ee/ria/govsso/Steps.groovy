package ee.ria.govsso

import com.google.common.hash.Hashing
import com.nimbusds.jwt.SignedJWT
import io.qameta.allure.Step
import io.restassured.response.Response

import java.nio.charset.StandardCharsets

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.anyOf
import static org.hamcrest.Matchers.containsString


class Steps {

    @Step("Initialize authentication sequence in SSO OIDC service with params")
    static Response startAuthenticationInSsoOidcWithParams(Flow flow, Map<String, String> paramsMap) {
        Response oidcAuth = Requests.getRequestWithCookiesAndParams(flow, flow.ssoOidcService.fullAuthenticationRequestUrl, flow.ssoOidcService.getCookies(), paramsMap, Collections.emptyMap())
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_authentication_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt(), oidcAuth.getCookie("oauth2_authentication_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt()))
        flow.setLoginChallenge(Utils.getParamValueFromResponseHeader(oidcAuth, "login_challenge"))
        return oidcAuth
    }

    @Step("Initialize authentication sequence in SSO OIDC service with params and origin headers")
    static Response startAuthenticationInSsoOidcWithParamsAndOrigin(Flow flow, Map<String, String> paramsMap, String origin) {
        Response oidcAuth = Requests.getRequestWithCookiesParamsAndOrigin(flow, flow.ssoOidcService.fullAuthenticationRequestUrl, flow.ssoOidcService.getCookies(), paramsMap, origin)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_authentication_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt(), oidcAuth.getCookie("oauth2_authentication_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt()))
        flow.setLoginChallenge(Utils.getParamValueFromResponseHeader(oidcAuth, "login_challenge"))
        return oidcAuth
    }

    @Step("Initialize authentication sequence in OIDC service with defaults")
    static Response startAuthenticationInSsoOidcWithDefaults(Flow flow) {
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        return startAuthenticationInSsoOidcWithParams(flow, paramsMap)
    }

    @Step("Initialize authentication sequence in OIDC service")
    static Response startAuthenticationInSsoOidc(Flow flow, String clientId, String fullResponseUrl) {
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, clientId, fullResponseUrl)
        return startAuthenticationInSsoOidcWithParams(flow, paramsMap)
    }

    @Step("Initialize authentication sequence in OIDC service with origin")
    static Response startAuthenticationInSsoOidcWithOrigin(Flow flow, String clientId, String fullResponseUrl, String origin) {
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, clientId, fullResponseUrl)
        return startAuthenticationInSsoOidcWithParamsAndOrigin(flow, paramsMap, origin)
    }

    @Step("Initialize authentication sequence in OIDC service")
    static Response startAuthenticationInSsoOidcWithScope(Flow flow, String clientId, String fullResponseUrl, String scope) {
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithScope(flow, clientId, fullResponseUrl, scope)
        return startAuthenticationInSsoOidcWithParams(flow, paramsMap)
    }

    @Step("Initialize session refresh sequence in OIDC service with defaults")
    static Response startSessionRefreshInSsoOidcWithDefaults(Flow flow, String idTokenHint, String origin) {
        Map<String, String> paramsMap = OpenIdUtils.getSessionRefreshParametersWithDefaults(flow, idTokenHint)
        return startAuthenticationInSsoOidcWithParamsAndOrigin(flow, paramsMap, origin)
    }

    @Step("Initialize session refresh sequence in OIDC service with scope")
    static Response startSessionRefreshInSsoOidcWithScope(Flow flow, String idTokenHint, String origin, String scope) {
        Map<String, String> paramsMap = OpenIdUtils.getSessionRefreshParametersWithScope(flow, idTokenHint, scope)
        return startAuthenticationInSsoOidcWithParamsAndOrigin(flow, paramsMap, origin)
    }

    @Step("Initialize session refresh sequence in OIDC service")
    static Response startSessionRefreshInSsoOidc(Flow flow, String idTokenHint, String clientId, String fullResponseUrl) {
        Map<String, String> paramsMap = OpenIdUtils.getSessionRefreshParameters(flow, idTokenHint, clientId, fullResponseUrl)
        return startAuthenticationInSsoOidcWithParams(flow, paramsMap)
    }

    @Step("Initialize session in session service")
    static Response startSessionInSessionService(Flow flow, Response response) {
        Response initSession = followRedirectWithCookies(flow, response, flow.ssoOidcService.cookies)
        Utils.setParameter(flow.sessionService.cookies, "__Host-GOVSSO", initSession.getCookie("__Host-GOVSSO"))
        Utils.setParameter(flow.sessionService.cookies, "__Host-XSRF-TOKEN", initSession.getCookie("__Host-XSRF-TOKEN"))
        return initSession
    }

    @Step("Initialize session in session service with origin")
    static Response startSessionInSessionServiceWithOrigin(Flow flow, Response response, String origin) {
        Response initSession = followRedirectWithCookiesAndOrigin(flow, response, flow.ssoOidcService.cookies, origin)
        Utils.setParameter(flow.sessionService.cookies, "__Host-GOVSSO", initSession.getCookie("__Host-GOVSSO"))
        Utils.setParameter(flow.sessionService.cookies, "__Host-XSRF-TOKEN", initSession.getCookie("__Host-XSRF-TOKEN"))
        return initSession
    }

    @Step("Initialize session refresh and follow redirects to client application with defaults")
    static Response refreshSessionWithDefaults(Flow flow, String idTokenHint) {
        Response oidcRefreshSession = startSessionRefreshInSsoOidcWithDefaults(flow, idTokenHint, flow.oidcClientA.fullBaseUrl)
        Response initLogin = followRedirectWithOrigin(flow, oidcRefreshSession, flow.oidcClientA.fullBaseUrl)
        Response loginVerifier = followRedirectWithCookiesAndOrigin(flow, initLogin, flow.ssoOidcService.cookies, flow.oidcClientA.fullBaseUrl)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_consent_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt(), loginVerifier.getCookie("oauth2_consent_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt()))
        Response initConsent = followRedirectWithOrigin(flow, loginVerifier, flow.oidcClientA.fullBaseUrl)
        Response consentVerifier = followRedirectWithCookiesAndOrigin(flow, initConsent, flow.ssoOidcService.cookies, flow.oidcClientA.fullBaseUrl)
        return getIdentityTokenResponseWithDefaults(flow, consentVerifier)
    }

    @Step("Initialize session refresh and follow redirects to client application with scope")
    static Response refreshSessionWithScope(Flow flow, String idTokenHint, String scope) {
        Response oidcRefreshSession = startSessionRefreshInSsoOidcWithScope(flow, idTokenHint, flow.oidcClientA.fullBaseUrl, scope)
        Response initLogin = followRedirectWithOrigin(flow, oidcRefreshSession, flow.oidcClientA.fullBaseUrl)
        Response loginVerifier = followRedirectWithCookiesAndOrigin(flow, initLogin, flow.ssoOidcService.cookies, flow.oidcClientA.fullBaseUrl)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_consent_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt(), loginVerifier.getCookie("oauth2_consent_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt()))
        Response initConsent = followRedirectWithOrigin(flow, loginVerifier, flow.oidcClientA.fullBaseUrl)
        Response consentVerifier = followRedirectWithCookiesAndOrigin(flow, initConsent, flow.ssoOidcService.cookies, flow.oidcClientA.fullBaseUrl)
        return getIdentityTokenResponseWithDefaults(flow, consentVerifier)
    }

    @Step("Initialize logout sequence in OIDC")
    static Response startLogout(flow, String idTokenHint, String logoutRedirectUri) {
        HashMap<String, String> queryParamas = new HashMap<>()
        queryParamas.put("id_token_hint", idTokenHint)
        queryParamas.put("post_logout_redirect_uri", logoutRedirectUri)
        Response initLogout = Requests.getRequestWithParams(flow, flow.ssoOidcService.fullLogoutUrl, queryParamas, Collections.emptyMap())
        flow.setLogoutChallenge(Utils.getParamValueFromResponseHeader(initLogout, "logout_challenge"))
        return initLogout
    }

    @Step("Initialize logout sequence in OIDC with origin")
    static Response startLogoutWithOrigin(flow, String idTokenHint, String logoutRedirectUri, String origin) {
        HashMap<String, String> headersMap = new HashMap<>()
        headersMap.put("Origin", origin)
        HashMap<String, String> queryParamas = new HashMap<>()
        queryParamas.put("id_token_hint", idTokenHint)
        queryParamas.put("post_logout_redirect_uri", logoutRedirectUri)
        Response initLogout = Requests.getRequestWithHeadersAndParams(flow, flow.ssoOidcService.fullLogoutUrl, headersMap, queryParamas, Collections.emptyMap())
        flow.setLogoutChallenge(Utils.getParamValueFromResponseHeader(initLogout, "logout_challenge"))
        return initLogout
    }

    @Step("Getting OAuth2 cookies")
    static Response getOAuthCookies(flow, Response response) {
        Response oidcService = followRedirectWithCookies(flow, response, flow.taraService.cookies)
        Utils.setParameter(flow.taraService.cookies, "oauth2_consent_csrf", oidcService.getCookie("oauth2_consent_csrf"))
        return oidcService
    }

    @Step("Follow redirect")
    static Response followRedirect(Flow flow, Response response) {
        String location = response.then().extract().response().getHeader("location")
        return Requests.followRedirect(flow, location)
    }

    @Step("Follow session refresh redirect with origin")
    static Response followRedirectWithOrigin(Flow flow, Response response, String origin) {
        String location = response.then().extract().response().getHeader("location")
        return Requests.followRedirectWithOrigin(flow, location, origin)
    }

    @Step("Follow redirect with cookies")
    static Response followRedirectWithCookies(Flow flow, Response response, Map cookies) {
        String location = response.then().extract().response().getHeader("location")
        return Requests.followRedirectWithCookie(flow, location, cookies)
    }

    @Step("Follow redirect with cookies and origin")
    static Response followRedirectWithCookiesAndOrigin(Flow flow, Response response, Map cookies, String origin) {
        String location = response.then().extract().response().getHeader("location")
        return Requests.followRedirectWithCookiesAndOrigin(flow, location, cookies, origin)
    }

    @Step("Follow redirect with session id")
    static Response followRedirectWithAlteredQueryParameters(Flow flow, Response response, Map paramsMap) {
        String location = response.then().extract().response().getHeader("location")
        return Requests.followRedirectWithParams(flow, location, paramsMap)
    }

    @Step("Confirm or reject consent in GOVSSO")
    static Response submitConsentSso(Flow flow, boolean consentGiven) {
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "consent_given", consentGiven)
        return Requests.postRequestWithParams(flow, flow.sessionService.fullConsentConfirmUrl, formParamsMap)
    }

    @Step("Confirm or reject consent and finish authentication process in GOVSSO")
    static Response submitConsentAndFollowRedirectsSso(Flow flow, boolean consentGiven, Response consent) {
        if (consent.getStatusCode().toInteger() == 200) {
            consent = submitConsentSso(flow, consentGiven)
        }
        return followRedirectWithCookies(flow, consent, flow.ssoOidcService.cookies)
    }

    @Step("Get identity token response with defaults")
    static Response getIdentityTokenResponseWithDefaults(Flow flow, Response response) {
        String authorizationCode = Utils.getParamValueFromResponseHeader(response, "code")
        Response token = Requests.getWebTokenWithDefaults(flow, authorizationCode)
        SignedJWT signedJWT = SignedJWT.parse(token.getBody().jsonPath().get("id_token"))
        Utils.addJsonAttachment("Header", signedJWT.getHeader().toString())
        Utils.addJsonAttachment("Payload", signedJWT.getJWTClaimsSet().toString())
        return token
    }

    @Step("Get identity token")
    static Response getIdentityTokenResponse(Flow flow, Response response, String clientId, String clientSecret, String redirectUrl) {
        String authorizationCode = Utils.getParamValueFromResponseHeader(response, "code")
        Response token = Requests.getWebToken(flow, authorizationCode, clientId, clientSecret, redirectUrl)
        SignedJWT signedJWT = SignedJWT.parse(token.getBody().jsonPath().get("id_token"))
        Utils.addJsonAttachment("Header", signedJWT.getHeader().toString())
        Utils.addJsonAttachment("Payload", signedJWT.getJWTClaimsSet().toString())
        return token
    }

    @Step("Follow redirects to client application")
    static Response followRedirectsToClientApplication(Flow flow, Response authenticationFinishedResponse) {
        Response initLogin = followRedirectWithCookies(flow, authenticationFinishedResponse, flow.sessionService.cookies)
        Response loginVerifier = followRedirectWithCookies(flow, initLogin, flow.ssoOidcService.cookies)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_consent_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt(), loginVerifier.getCookie("oauth2_consent_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt()))
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_authentication_session", loginVerifier.getCookie("oauth2_authentication_session"))
        Response initConsent = followRedirectWithCookies(flow, loginVerifier, flow.ssoOidcService.cookies)
        return followRedirectWithCookies(flow, initConsent, flow.ssoOidcService.cookies)
    }

    @Step("Follow redirects to client application with existing session")
    static Response followRedirectsToClientApplicationWithExistingSession(Flow flow, Response response, String clientId, String clientSecret, String fullResponseUrl) {
        Response loginVerifier = followRedirectWithCookies(flow, response, flow.ssoOidcService.cookies)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_consent_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt(), loginVerifier.getCookie("oauth2_consent_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt()))
        Response initConsent = followRedirect(flow, loginVerifier)
        Response consentVerifier = followRedirectWithCookies(flow, initConsent, flow.ssoOidcService.cookies)
        return getIdentityTokenResponse(flow, consentVerifier, clientId, clientSecret, fullResponseUrl)
    }

    @Step("Create initial session in GOVSSO with ID-Card in client-A")
    static Response authenticateWithIdCardInGovsso(flow) {
        Response oidcAuth = startAuthenticationInSsoOidcWithDefaults(flow)
        Response initLogin = startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response consentVerifier = followRedirectsToClientApplication(flow, taraAuthentication)
        return getIdentityTokenResponseWithDefaults(flow, consentVerifier)
    }

    @Step("Create initial session in GOVSSO with ID-Card in client-A with custom ui_locales")
    static Response authenticateWithIdCardInGovssoWithUiLocales(Flow flow, String uiLocales) {
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.put("ui_locales", uiLocales)
        Response oidcAuth = startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response consentVerifier = followRedirectsToClientApplication(flow, taraAuthentication)
        return getIdentityTokenResponseWithDefaults(flow, consentVerifier)
    }

    @Step("Create initial session in GOVSSO with eIDAS in client-A")
    static Response authenticateWithEidasInGovsso(flow, String acrValue, String eidasLoa) {
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.put("acr_values", acrValue)
        Response oidcAuth = startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithEidasInTARA(flow, "CA", "xavi", "creus", eidasLoa, initLogin)
        Response consentVerifier = followRedirectsToClientApplication(flow, taraAuthentication)
        return getIdentityTokenResponseWithDefaults(flow, consentVerifier)
    }

    @Step("Create initial session in GOVSSO with eIDAS in client-A with custom ui_locales")
    static Response authenticateWithEidasInGovssoWithUiLocales(flow, String acrValue, String eidasLoa, uiLocales) {
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        Utils.setParameter(paramsMap, "ui_locales", uiLocales)
        Utils.setParameter(paramsMap, "acr_values", acrValue)
        Response oidcAuth = startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithEidasInTARA(flow, "CA", "xavi", "creus", eidasLoa, initLogin)
        Response consentVerifier = followRedirectsToClientApplication(flow, taraAuthentication)
        return getIdentityTokenResponseWithDefaults(flow, consentVerifier)
    }

    @Step("Use existing session to authenticate to another client")
    static Response continueWithExistingSession(Flow flow, String clientId, String clientSecret, String fullResponseUrl) {
        Response oidcAuth = startAuthenticationInSsoOidc(flow, clientId, fullResponseUrl)
        followRedirect(flow, oidcAuth)
        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", flow.getLoginChallenge().toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))
        Response continueSession = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies, formParams)
        return followRedirectsToClientApplicationWithExistingSession(flow, continueSession, clientId, clientSecret, fullResponseUrl)
    }

    @Step("Use existing session to authenticate to another client with scope")
    static Response continueWithExistingSessionWithScope(Flow flow, String clientId, String clientSecret, String fullResponseUrl, String scope) {
        Response oidcAuth = startAuthenticationInSsoOidcWithScope(flow, clientId, fullResponseUrl, scope)
        followRedirect(flow, oidcAuth)
        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", flow.getLoginChallenge().toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))
        Response continueSession = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies, formParams)
        return followRedirectsToClientApplicationWithExistingSession(flow, continueSession, clientId, clientSecret, fullResponseUrl)
    }

    @Step("Initialize logout with session in several GSSO clients and follow redirects")
    static Response logout(Flow flow, String idTokenHint, String logoutRedirectUri, String logoutTypeUrl) {
        Response oidcLogout = startLogout(flow, idTokenHint, logoutRedirectUri)
        followRedirect(flow, oidcLogout)
        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "logoutChallenge", flow.getLogoutChallenge().toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))
        return Requests.postRequestWithParams(flow, logoutTypeUrl, formParams)
    }

    @Step("Initialize logout with session for a single client")
    static Response logoutSingleClientSession(Flow flow, String idTokenHint, String logoutRedirectUri) {
        Response oidcLogout = startLogout(flow, idTokenHint, logoutRedirectUri)
        Response initLogout = followRedirect(flow, oidcLogout)
        return followRedirect(flow, initLogout)
    }

    @Step("Initialize reauthentication sequence and follow redirects to client application")
    static Response reauthenticate(Flow flow, String clientId, String clientSecret, String fullResponseUrl) {
        Response oidcAuth = startAuthenticationInSsoOidc(flow, clientId, fullResponseUrl)
        followRedirect(flow, oidcAuth)
        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", flow.getLoginChallenge().toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))
        Response reauthenticate = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullReauthenticateUrl, flow.sessionService.cookies, formParams)
        Response initLogin = followRedirectWithCookies(flow, reauthenticate, flow.ssoOidcService.cookies)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_authentication_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt(), initLogin.getCookie("oauth2_authentication_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt()))
        Response followRedirect = followRedirect(flow, initLogin)
        Utils.setParameter(flow.sessionService.cookies, "__Host-GOVSSO", followRedirect.getCookie("__Host-GOVSSO"))
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, followRedirect)
        Response consentVerifier = followRedirectsToClientApplication(flow, taraAuthentication)
        return getIdentityTokenResponse(flow, consentVerifier, clientId, clientSecret, fullResponseUrl)
    }

    @Step("Initialize reauthentication sequence and follow redirects to client application after acr discrepancy")
    static Response reauthenticateAfterAcrDiscrepancy(Flow flow) {
        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", flow.getLoginChallenge().toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))
        Response reauthenticate = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullReauthenticateUrl, flow.ssoOidcService.cookies, formParams)
        Response oidcAuth2 = followRedirect(flow, reauthenticate)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_authentication_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt(), oidcAuth2.getCookie("oauth2_authentication_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt()))
        Response initLogin = followRedirectWithCookies(flow, oidcAuth2, flow.ssoOidcService.cookies)
        Utils.setParameter(flow.sessionService.cookies, "__Host-GOVSSO", initLogin.getCookie("__Host-GOVSSO"))
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response consentVerifier = followRedirectsToClientApplication(flow, taraAuthentication)
        return getIdentityTokenResponse(flow, consentVerifier, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
    }

    @Step("Verify session service response headers")
    static void verifyResponseHeaders(Response response) {
        assertThat(response.getHeader("X-Frame-Options"), equalTo("DENY"))
        String policyString = "connect-src 'self'; default-src 'none'; font-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; block-all-mixed-content"
        assertThat(response.getHeader("Content-Security-Policy"), equalTo(policyString))
        assertThat(response.getHeader("Strict-Transport-Security"), anyOf(containsString("max-age=16070400"), containsString("max-age=31536000")))
        assertThat(response.getHeader("Strict-Transport-Security"), containsString("includeSubDomains"))
        assertThat(response.getHeader("Cache-Control"), equalTo("no-cache, no-store, max-age=0, must-revalidate"))
        assertThat(response.getHeader("X-Content-Type-Options"), equalTo("nosniff"))
        assertThat(response.getHeader("X-XSS-Protection"), equalTo("0"))
    }
}
