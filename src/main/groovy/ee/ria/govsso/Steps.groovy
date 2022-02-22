package ee.ria.govsso


import com.nimbusds.jwt.SignedJWT
import io.qameta.allure.Feature
import io.qameta.allure.Step
import io.restassured.response.Response
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.anyOf
import static org.hamcrest.Matchers.containsString


class Steps {

    @Step("Initialize authentication sequence in SSO OIDC service with params")
    static Response startAuthenticationInSsoOidcWithParams(Flow flow, Map<String, String> paramsMap) {
        Response initSession = Requests.getRequestWithCookiesAndParams(flow, flow.ssoOidcService.fullAuthenticationRequestUrl, flow.ssoOidcService.getCookies(), paramsMap, Collections.emptyMap())
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_authentication_csrf", initSession.getCookie("oauth2_authentication_csrf"))
        flow.setLoginChallenge(Utils.getParamValueFromResponseHeader(initSession, "login_challenge"))
        return initSession
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

    @Step("Initialize session refresh sequence in OIDC service with defaults")
    static Response startSessionRefreshInSsoOidcWithDefaults(Flow flow, String idTokenHint) {
        Map<String, String> paramsMap = OpenIdUtils.getSessionRefreshParametersWithDefaults(flow, idTokenHint)
        return startAuthenticationInSsoOidcWithParams(flow, paramsMap)
    }

    @Step("Initialize session refresh sequence in OIDC service")
    static Response startSessionRefreshInSsoOidc(Flow flow, String idTokenHint, String clientId, String fullResponseUrl) {
        Map<String, String> paramsMap = OpenIdUtils.getSessionRefreshParameters(flow, idTokenHint, clientId, fullResponseUrl)
        return startAuthenticationInSsoOidcWithParams(flow, paramsMap)
    }

    @Step("Initialize session in session service with params")
    static Response startSessionInSessionService(Flow flow, Response response) {
        Response initSession = followRedirectWithCookies(flow, response, flow.ssoOidcService.cookies)
        Utils.setParameter(flow.sessionService.cookies, "__Host-GOVSSO", initSession.getCookie("__Host-GOVSSO"))
        Utils.setParameter(flow.sessionService.cookies, "__Host-XSRF-TOKEN", initSession.getCookie("__Host-XSRF-TOKEN"))
        return initSession
    }

    @Step("Initialize session refresh and follow redirects to client application with defaults")
    static Response refreshSessionWithDefaults(Flow flow, String idTokenHint) {
        Response initRefreshSession = startSessionRefreshInSsoOidcWithDefaults(flow, idTokenHint)
        Response initLoginResponse = followRedirect(flow, initRefreshSession)
        Response oauthLoginResponse = followRedirect(flow, initLoginResponse)
        Response initConsentResponse = followRedirect(flow, oauthLoginResponse)
        Response oauthConsentResponse = followRedirect(flow, initConsentResponse)
        return getIdentityTokenResponseWithDefaults(flow, oauthConsentResponse)

    }

    @Step("Initialize session refresh and follow redirects to client application")
    static Response refreshSession(Flow flow, String idTokenHint, String clientId, String fullResponseUrl) {
        Response initRefreshSession = startSessionRefreshInSsoOidc(flow, idTokenHint, clientId, fullResponseUrl)
        Response initLoginResponse = followRedirect(flow, initRefreshSession)
        Response oauthLoginResponse = followRedirect(flow, initLoginResponse)
        Response initConsentResponse = followRedirect(flow, oauthLoginResponse)
        Response oauthConsentResponse = followRedirect(flow, initConsentResponse)
        return getIdentityTokenResponseWithDefaults(flow, oauthConsentResponse)

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

    @Step("Getting OAuth2 cookies")
    static Response getOAuthCookies(flow, Response response) {
        Response oidcServiceResponse = followRedirectWithCookies(flow, response, flow.taraService.cookies)
        Utils.setParameter(flow.taraService.cookies, "oauth2_consent_csrf", oidcServiceResponse.getCookie("oauth2_consent_csrf"))
        return oidcServiceResponse
    }

    @Step("Follow redirect")
    static Response followRedirect(Flow flow, Response response) {
        String location = response.then().extract().response().getHeader("location")
        return Requests.followRedirect(flow, location)
    }

    @Step("Follow redirect with cookies")
    static Response followRedirectWithSsoSessionCookies(Flow flow, Response response, Map cookies) {
        String location = response.then().extract().response().getHeader("location")
        return Requests.followRedirectWithCookie(flow, location, cookies)
    }

    @Step("Follow redirect with cookies")
    static Response followRedirectWithCookies(Flow flow, Response response, Map cookies) {
        String location = response.then().extract().response().getHeader("location")
        return Requests.followRedirectWithCookie(flow, location, cookies)
    }

    @Step("Follow redirect with session id")
    static Response followRedirectWithSessionId(Flow flow, Response response) {
        String location = response.then().extract().response().getHeader("location")
        return Requests.getRequestWithSessionId(flow, location)
    }

    @Step("Confirm or reject consent in GOVSSO")
    static Response submitConsentSso(Flow flow, boolean consentGiven) {
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "consent_given", consentGiven)
        return Requests.postRequestWithParams(flow, flow.sessionService.fullConsentConfirmUrl, formParamsMap)
    }

    @Step("Confirm or reject consent and finish authentication process in GOVSSO")
    static Response submitConsentAndFollowRedirectsSso(Flow flow, boolean consentGiven, Response consentResponse) {
        if (consentResponse.getStatusCode().toInteger() == 200) {
            consentResponse = submitConsentSso(flow, consentGiven)
        }
        return followRedirectWithSsoSessionCookies(flow, consentResponse, flow.ssoOidcService.cookies)
    }

    @Step("Get identity token response with defaults")
    static Response getIdentityTokenResponseWithDefaults(Flow flow, Response response) {
        String authorizationCode = Utils.getParamValueFromResponseHeader(response, "code")
        Response webTokenResponse = Requests.getWebTokenWithDefaults(flow, authorizationCode)
        SignedJWT signedJWT = SignedJWT.parse(webTokenResponse.getBody().jsonPath().get("id_token"))
        Utils.addJsonAttachment("Header", signedJWT.getHeader().toString())
        Utils.addJsonAttachment("Payload", signedJWT.getJWTClaimsSet().toString())
        return webTokenResponse
    }

    @Step("Get identity token")
    static Response getIdentityTokenResponse(Flow flow, Response response, String clientId, String clientSecret, String redirectUrl) {
        String authorizationCode = Utils.getParamValueFromResponseHeader(response, "code")
        Response webTokenResponse = Requests.getWebToken(flow, authorizationCode, clientId, clientSecret, redirectUrl)
        SignedJWT signedJWT = SignedJWT.parse(webTokenResponse.getBody().jsonPath().get("id_token"))
        Utils.addJsonAttachment("Header", signedJWT.getHeader().toString())
        Utils.addJsonAttachment("Payload", signedJWT.getJWTClaimsSet().toString())
        return webTokenResponse
    }

    @Step("Follow redirects to client application")
    static Response followRedirectsToClientApplication(Flow flow, Response authenticationFinishedResponse) {
        Response sessionServiceResponse = followRedirectWithCookies(flow, authenticationFinishedResponse, flow.sessionService.cookies)
        verifyResponseHeaders(sessionServiceResponse)
        Response oidcServiceResponse = followRedirectWithCookies(flow, sessionServiceResponse, flow.ssoOidcService.cookies)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_consent_csrf", oidcServiceResponse.getCookie("oauth2_consent_csrf"))
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_authentication_session", oidcServiceResponse.getCookie("oauth2_authentication_session"))
        Response sessionServiceConsentResponse = followRedirectWithCookies(flow, oidcServiceResponse, flow.ssoOidcService.cookies)
        verifyResponseHeaders(sessionServiceResponse)
        return followRedirectWithCookies(flow, sessionServiceConsentResponse, flow.ssoOidcService.cookies)
    }

    @Step("Follow redirects to client application with existing session")
    static Response followRedirectsToClientApplicationWithExistingSession(Flow flow, Response response, String clientId, String clientSecret, String fullResponseUrl) {
        Response oidcServiceResponse1 = followRedirect(flow, response)
        Response consentResponse = followRedirect(flow, oidcServiceResponse1)
        Response oidcServiceResponse2 = followRedirect(flow, consentResponse)
        return getIdentityTokenResponse(flow, oidcServiceResponse2, clientId, clientSecret, fullResponseUrl)
    }

    @Step("Create initial session in GOVSSO with ID-Card in client-A")
    static Response authenticateWithIdCardInGovsso(flow) {
        Response oidcServiceInitResponse = startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = startSessionInSessionService(flow, oidcServiceInitResponse)
        verifyResponseHeaders(sessionServiceRedirectToTaraResponse)
        Response authenticationFinishedResponse = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)
        Response oidcServiceConsentResponse = followRedirectsToClientApplication(flow, authenticationFinishedResponse)
        return getIdentityTokenResponseWithDefaults(flow, oidcServiceConsentResponse)
    }

    @Step("Create initial session in GOVSSO with ID-Card in client-A with custom ui_locales")
    static Response authenticateWithIdCardInGovssoWithUiLocales(flow, String uiLocales) {
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.put("ui_locales", uiLocales)
        Response oidcServiceInitResponse = startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response sessionServiceRedirectToTaraResponse = startSessionInSessionService(flow, oidcServiceInitResponse)
        verifyResponseHeaders(sessionServiceRedirectToTaraResponse)
        Response authenticationFinishedResponse = TaraSteps.authenticateWithIdCardInTARA(flow, sessionServiceRedirectToTaraResponse)
        Response oidcServiceConsentResponse = followRedirectsToClientApplication(flow, authenticationFinishedResponse)
        return getIdentityTokenResponseWithDefaults(flow, oidcServiceConsentResponse)
    }

    @Step("Create initial session in GOVSSO with eIDAS in client-A")
    static Response authenticateWithEidasInGovsso(flow, String acrValue, String eidasLoa) {
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap.put("acr_values", acrValue)
        Response oidcServiceInitResponse = startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response sessionServiceRedirectToTaraResponse = startSessionInSessionService(flow, oidcServiceInitResponse)
        Response authenticationFinishedResponse = TaraSteps.authenticateWithEidasInTARA(flow, "CA", "xavi", "creus", eidasLoa, sessionServiceRedirectToTaraResponse)
        Response oidcServiceConsentResponse = followRedirectsToClientApplication(flow, authenticationFinishedResponse)
        return getIdentityTokenResponseWithDefaults(flow, oidcServiceConsentResponse)
    }

    @Step("Use existing session to authenticate to another client")
    static Response continueWithExistingSession(Flow flow, String clientId, String clientSecret, String fullResponseUrl) {
        Response oidcServiceInitResponse = startAuthenticationInSsoOidc(flow, clientId, fullResponseUrl)
        followRedirect(flow, oidcServiceInitResponse)
        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", flow.getLoginChallenge().toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))
        Response continueWithExistingSession = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies, formParams)
        return followRedirectsToClientApplicationWithExistingSession(flow, continueWithExistingSession, clientId, clientSecret, fullResponseUrl)
    }

    @Step("Initialize logout with session in several GSSO clients and follow redirects")
    static Response logout(Flow flow, String idTokenHint, String logoutRedirectUri, String logoutTypeUrl) {
        Response initLogoutOidc = startLogout(flow, idTokenHint, logoutRedirectUri)
        followRedirect(flow, initLogoutOidc)
        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "logoutChallenge", flow.getLogoutChallenge().toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))
        return Requests.postRequestWithParams(flow, logoutTypeUrl, formParams)
    }

    @Step("Initialize logout with session for a single client")
    static Response logoutSingleClientSession(Flow flow, String idTokenHint, String logoutRedirectUri) {
        Response initLogoutOidc = startLogout(flow, idTokenHint, logoutRedirectUri)
        Response initLogoutSession = followRedirect(flow, initLogoutOidc)
        return followRedirect(flow, initLogoutSession)
    }

    @Step("Initialize reauthentication sequence and follow redirects to client application")
    static Response reauthenticate(Flow flow, String clientId, String clientSecret, String fullResponseUrl) {
        Response oidcServiceInitResponse = startAuthenticationInSsoOidc(flow, clientId, fullResponseUrl)
        followRedirect(flow, oidcServiceInitResponse)
        HashMap<String, String> formParams = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParams, "loginChallenge", flow.getLoginChallenge().toString())
        Utils.setParameter(formParams, "_csrf", flow.sessionService.getCookies().get("__Host-XSRF-TOKEN"))
        Response reauthenticateResponse = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullReauthenticateUrl, flow.sessionService.cookies, formParams)
        Response sessionServiceRedirectToTaraResponse = followRedirectWithCookies(flow, reauthenticateResponse, flow.ssoOidcService.cookies)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_authentication_csrf", sessionServiceRedirectToTaraResponse.getCookie("oauth2_authentication_csrf"))
        Response followRedirect = followRedirect(flow, sessionServiceRedirectToTaraResponse)
        Utils.setParameter(flow.sessionService.cookies, "__Host-GOVSSO", followRedirect.getCookie("__Host-GOVSSO"))
        Response authenticationFinishedResponse = TaraSteps.authenticateWithIdCardInTARA(flow, followRedirect)
        Response oidcServiceConsentResponse = followRedirectsToClientApplication(flow, authenticationFinishedResponse)
        return getIdentityTokenResponse(flow, oidcServiceConsentResponse, clientId, clientSecret, fullResponseUrl)
    }

    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("DISALLOW_IFRAMES")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    @Step("verify response headers")
    static void verifyResponseHeaders(Response response) {
        assertThat(response.getHeader("X-Frame-Options"), equalTo("DENY"))
        String policyString = "connect-src 'self'; default-src 'none'; font-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; block-all-mixed-content"
        assertThat(response.getHeader("Content-Security-Policy"), equalTo(policyString))
        assertThat(response.getHeader("Strict-Transport-Security"), anyOf(containsString("max-age=16070400"), containsString("max-age=31536000")))
        assertThat(response.getHeader("Strict-Transport-Security"), containsString("includeSubDomains"))
        assertThat(response.getHeader("Cache-Control"), equalTo("no-cache, no-store, max-age=0, must-revalidate"))
        assertThat(response.getHeader("X-Content-Type-Options"), equalTo("nosniff"))
        assertThat(response.getHeader("X-XSS-Protection"), equalTo("0"))
    }
}
