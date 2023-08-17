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
    static Response startAuthenticationInSsoOidcWithParams(Flow flow, Map paramsMap) {
        Response oidcAuth = Requests.getRequestWithCookiesAndParams(flow, flow.ssoOidcService.fullAuthenticationRequestUrl, flow.ssoOidcService.cookies, paramsMap)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_authentication_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt(), oidcAuth.cookie("oauth2_authentication_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt()))
        flow.setLoginChallenge(Utils.getParamValueFromResponseHeader(oidcAuth, "login_challenge"))
        return oidcAuth
    }

    @Step("Initialize authentication sequence in SSO OIDC service with params and origin headers")
    static Response startAuthenticationInSsoOidcWithParamsAndOrigin(Flow flow, Map paramsMap, String origin) {
        Response oidcAuth = Requests.getRequestWithCookiesParamsAndOrigin(flow, flow.ssoOidcService.fullAuthenticationRequestUrl, flow.ssoOidcService.cookies, paramsMap, origin)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_authentication_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt(), oidcAuth.cookie("oauth2_authentication_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt()))
        flow.setLoginChallenge(Utils.getParamValueFromResponseHeader(oidcAuth, "login_challenge"))
        return oidcAuth
    }

    @Step("Initialize authentication sequence in OIDC service with defaults")
    static Response startAuthenticationInSsoOidcWithDefaults(Flow flow) {
        Map paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        return startAuthenticationInSsoOidcWithParams(flow, paramsMap)
    }

    @Step("Initialize authentication sequence in OIDC service")
    static Response startAuthenticationInSsoOidc(Flow flow, String clientId, String fullResponseUrl) {
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, clientId, fullResponseUrl)
        return startAuthenticationInSsoOidcWithParams(flow, paramsMap)
    }

    @Step("Initialize authentication sequence in OIDC service with origin")
    static Response startAuthenticationInSsoOidcWithOrigin(Flow flow, String clientId, String fullResponseUrl, String origin) {
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, clientId, fullResponseUrl)
        return startAuthenticationInSsoOidcWithParamsAndOrigin(flow, paramsMap, origin)
    }

    @Step("Initialize authentication sequence in OIDC service")
    static Response startAuthenticationInSsoOidcWithScope(Flow flow, String clientId, String fullResponseUrl, String scope) {
        Map paramsMap = OpenIdUtils.getAuthorizationParametersWithScope(flow, clientId, fullResponseUrl, scope)
        return startAuthenticationInSsoOidcWithParams(flow, paramsMap)
    }

    @Step("Initialize session update sequence in OIDC service with defaults")
    static Response startSessionUpdateInSsoOidcWithDefaults(Flow flow, String idTokenHint, String origin) {
        Map paramsMap = OpenIdUtils.getSessionUpdateParametersWithDefaults(flow, idTokenHint)
        return startAuthenticationInSsoOidcWithParamsAndOrigin(flow, paramsMap, origin)
    }

    @Step("Initialize session in session service")
    static Response startSessionInSessionService(Flow flow, Response response) {
        Response initSession = followRedirectWithCookies(flow, response, flow.ssoOidcService.cookies)
        Utils.setParameter(flow.sessionService.cookies, "__Host-AUTH", initSession.cookie("__Host-AUTH"))
        Utils.setParameter(flow.sessionService.cookies, "__Host-XSRF-TOKEN", initSession.cookie("__Host-XSRF-TOKEN"))
        return initSession
    }

    @Step("Initialize session in session service with origin")
    static Response startSessionInSessionServiceWithOrigin(Flow flow, Response response, String origin) {
        Response initSession = followRedirectWithCookiesAndOrigin(flow, response, flow.ssoOidcService.cookies, origin)
        Utils.setParameter(flow.sessionService.cookies, "__Host-AUTH", initSession.cookie("__Host-AUTH"))
        Utils.setParameter(flow.sessionService.cookies, "__Host-XSRF-TOKEN", initSession.cookie("__Host-XSRF-TOKEN"))
        return initSession
    }

    @Step("Initialize logout sequence in OIDC")
    static Response startLogout(Flow flow, String idTokenHint, String logoutRedirectUri) {
        Map queryParams = [id_token_hint           : idTokenHint,
                           post_logout_redirect_uri: logoutRedirectUri]
        Response initLogout = Requests.getRequestWithParams(flow, flow.ssoOidcService.fullLogoutUrl, queryParams)
        if (initLogout.statusCode == 302 && initLogout.header("Location") != logoutRedirectUri) {
            flow.setLogoutChallenge(Utils.getParamValueFromResponseHeader(initLogout, "logout_challenge"))
        }
        return initLogout
    }

    @Step("Initialize logout sequence in OIDC with origin")
    static Response startLogoutWithOrigin(Flow flow, String idTokenHint, String logoutRedirectUri, String origin) {
        Map headersMap = [Origin: origin]
        Map queryParams = [id_token_hint           : idTokenHint,
                           post_logout_redirect_uri: logoutRedirectUri]
        Response initLogout = Requests.getRequestWithHeadersAndParams(flow, flow.ssoOidcService.fullLogoutUrl, headersMap, queryParams)
        flow.setLogoutChallenge(Utils.getParamValueFromResponseHeader(initLogout, "logout_challenge"))
        return initLogout
    }

    @Step("Follow redirect")
    static Response followRedirect(Flow flow, Response response) {
        String location = response.then().extract().response().header("location")
        return Requests.followRedirect(flow, location)
    }

    @Step("Follow redirect with origin")
    static Response followRedirectWithOrigin(Flow flow, Response response, String origin) {
        String location = response.then().extract().response().header("location")
        return Requests.followRedirectWithOrigin(flow, location, origin)
    }

    @Step("Follow redirect with cookies")
    static Response followRedirectWithCookies(Flow flow, Response response, Map cookies) {
        String location = response.then().extract().response().header("location")
        return Requests.followRedirectWithCookies(flow, location, cookies)
    }

    @Step("Follow redirect with cookies and origin")
    static Response followRedirectWithCookiesAndOrigin(Flow flow, Response response, Map cookies, String origin) {
        String location = response.then().extract().response().header("location")
        return Requests.followRedirectWithCookiesAndOrigin(flow, location, cookies, origin)
    }

    @Step("Follow redirect with session id")
    static Response followRedirectWithAlteredQueryParameters(Flow flow, Response response, Map paramsMap) {
        String location = response.then().extract().response().header("location")
        return Requests.followRedirectWithParams(flow, location, paramsMap)
    }

    @Step("Get identity token response with defaults")
    static Response getIdentityTokenResponseWithDefaults(Flow flow,
                                                         Response response,
                                                         String clientId = flow.oidcClientA.clientId,
                                                         String clientSecret = flow.oidcClientA.clientSecret,
                                                         String fullResponseUrl = flow.oidcClientA.fullResponseUrl) {
        String authorizationCode = Utils.getParamValueFromResponseHeader(response, "code")
        Response token = Requests.getAuthenticationWebToken(flow, authorizationCode, clientId, clientSecret, fullResponseUrl)
        flow.setRefreshToken(token.jsonPath().get("refresh_token"))
        flow.setIdToken(token.jsonPath().get("id_token"))
        SignedJWT signedJWT = SignedJWT.parse(token.body.jsonPath().get("id_token"))
        Utils.addJsonAttachment("Header", signedJWT.header.toString())
        Utils.addJsonAttachment("Payload", signedJWT.JWTClaimsSet.toString())
        return token
    }

    @Step("Update session with defaults")
    static Response getSessionUpdateResponse(Flow flow) {
        return getSessionUpdateResponse(flow,
                flow.refreshToken,
                flow.oidcClientA.clientId,
                flow.oidcClientA.clientSecret,
                flow.oidcClientA.fullBaseUrl)
    }

    @Step("Update session")
    static Response getSessionUpdateResponse(Flow flow, String refreshToken, String clientId, String clientSecret, String redirectUrl) {
        Response tokenResponse = Requests.getSessionUpdateWebToken(flow, refreshToken, clientId, clientSecret, redirectUrl)
        if (tokenResponse.statusCode != 200) {
            return tokenResponse
        } else {
            SignedJWT signedJWT = SignedJWT.parse(tokenResponse.body.jsonPath().get("id_token"))
            Utils.addJsonAttachment("Header", signedJWT.header.toString())
            Utils.addJsonAttachment("Payload", signedJWT.JWTClaimsSet.toString())
            return tokenResponse
        }
    }

    @Step("Follow redirects to token request")
    static Response followRedirectsToClientApplication(Flow flow,
                                                       Response response,
                                                       String clientId = flow.oidcClientA.clientId,
                                                       String clientSecret = flow.oidcClientA.clientSecret,
                                                       String fullResponseUrl = flow.oidcClientA.fullResponseUrl) {
        Response initLogin = followRedirectWithCookies(flow, response, flow.sessionService.cookies)
        Response loginVerifier = followRedirectWithCookies(flow, initLogin, flow.ssoOidcService.cookies)
        flow.setConsentChallenge(Utils.getParamValueFromResponseHeader(loginVerifier, "consent_challenge"))
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_consent_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt(), loginVerifier.cookie("oauth2_consent_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt()))
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_authentication_session", loginVerifier.cookie("oauth2_authentication_session"))
        Response initConsent = followRedirectWithCookies(flow, loginVerifier, flow.ssoOidcService.cookies)
        Response consentVerifier = followRedirectWithCookies(flow, initConsent, flow.ssoOidcService.cookies)
        return getIdentityTokenResponseWithDefaults(flow, consentVerifier, clientId, clientSecret, fullResponseUrl)
    }

    @Step("Follow redirects to client application with existing session")
    static Response followRedirectsToClientApplicationWithExistingSession(Flow flow, Response response, String clientId, String clientSecret, String fullResponseUrl) {
        Response loginVerifier = followRedirectWithCookies(flow, response, flow.ssoOidcService.cookies)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_consent_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt(), loginVerifier.cookie("oauth2_consent_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt()))
        Response initConsent = followRedirect(flow, loginVerifier)
        Response consentVerifier = followRedirectWithCookies(flow, initConsent, flow.ssoOidcService.cookies)
        return getIdentityTokenResponseWithDefaults(flow, consentVerifier, clientId, clientSecret, fullResponseUrl)
    }

    @Step("Create initial session in GovSSO with ID-Card in client-A")
    static Response authenticateWithIdCardInGovSso(Flow flow) {
        Response oidcAuth = startAuthenticationInSsoOidcWithDefaults(flow)
        Response initLogin = startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        return followRedirectsToClientApplication(flow, taraAuthentication)
    }

    @Step("Create initial session in GovSSO with ID-Card in client-A with custom ui_locales")
    static Response authenticateWithIdCardInGovSsoWithUiLocales(Flow flow, String uiLocales) {
        Map paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap << [ui_locales: uiLocales]
        Response oidcAuth = startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        return followRedirectsToClientApplication(flow, taraAuthentication)
    }

    @Step("Create initial session in GovSSO with eIDAS in client-A")
    static Response authenticateWithEidasInGovSso(Flow flow, String acrValue, String eidasLoa) {
        Map paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap << [acr_values: acrValue]
        Response oidcAuth = startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithEidasInTARA(flow, "CA", "xavi", "creus", eidasLoa, initLogin)
        return followRedirectsToClientApplication(flow, taraAuthentication)
    }

    @Step("Create initial session in GovSSO with eIDAS in client-A with custom ui_locales")
    static Response authenticateWithEidasInGovSsoWithUiLocales(Flow flow, String acrValue, String eidasLoa, uiLocales) {
        Map paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        paramsMap << [ui_locales: uiLocales,
                      acr_values: acrValue]
        Response oidcAuth = startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithEidasInTARA(flow, "CA", "xavi", "creus", eidasLoa, initLogin)
        return followRedirectsToClientApplication(flow, taraAuthentication)
    }

    @Step("Use existing session to authenticate to another client")
    static Response continueWithExistingSession(Flow flow, String clientId = flow.oidcClientB.clientId, String clientSecret = flow.oidcClientB.clientSecret, String responseUrl = flow.oidcClientB.fullResponseUrl) {
        Response oidcAuth = startAuthenticationInSsoOidc(flow, clientId, responseUrl)
        if (clientId != flow.oidcClientB.clientId && clientId != flow.oidcClientA.clientId) {
            return followRedirectsToClientApplication(flow, oidcAuth, clientId, clientSecret, responseUrl)
        } else {
            Response redirectResponse = followRedirect(flow, oidcAuth)
            if (redirectResponse.statusCode != 200) {
                return redirectResponse
            } else {
                Map formParams = [loginChallenge: flow.loginChallenge,
                                  _csrf         : flow.sessionService.cookies.get("__Host-XSRF-TOKEN")]
                Response continueSession = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies, formParams)
                return followRedirectsToClientApplicationWithExistingSession(flow, continueSession, clientId, clientSecret, responseUrl)
            }
        }
    }

    @Step("Use existing session to authenticate to another client with scope")
    static Response continueWithExistingSessionWithScope(Flow flow, String clientId, String clientSecret, String responseUrl, String scope) {
        Response oidcAuth = startAuthenticationInSsoOidcWithScope(flow, clientId, responseUrl, scope)
        followRedirect(flow, oidcAuth)
        Map formParams = [loginChallenge: flow.loginChallenge,
                          _csrf         : flow.sessionService.cookies.get("__Host-XSRF-TOKEN")]
        Response continueSession = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullContinueSessionUrl, flow.sessionService.cookies, formParams)
        return followRedirectsToClientApplicationWithExistingSession(flow, continueSession, clientId, clientSecret, responseUrl)
    }

    @Step("Initialize logout with session in several GSSO clients and follow redirects")
    static Response logout(Flow flow, String idTokenHint, String logoutRedirectUri, String logoutTypeUrl) {
        Response oidcLogout = startLogout(flow, idTokenHint, logoutRedirectUri)
        followRedirect(flow, oidcLogout)
        Map formParams = [logoutChallenge: flow.logoutChallenge,
                          _csrf          : flow.sessionService.cookies.get("__Host-XSRF-TOKEN")]
        return Requests.postRequestWithParams(flow, logoutTypeUrl, formParams)
    }

    @Step("Initialize logout with session for a single client")
    static Response logoutSingleClientSession(Flow flow, String idTokenHint, String logoutRedirectUri) {
        Response oidcLogout = startLogout(flow, idTokenHint, logoutRedirectUri)
        Response initLogout = followRedirect(flow, oidcLogout)
        return followRedirect(flow, initLogout)
    }

    @Step("Initialize logout with session for client-A")
    static Response logoutSingleClientSession(Flow flow) {
        Response oidcLogout = startLogout(flow, flow.idToken, flow.oidcClientA.fullLogoutRedirectUrl)
        Response initLogout = followRedirect(flow, oidcLogout)
        return followRedirect(flow, initLogout)
    }

    @Step("Initialize reauthentication sequence and follow redirects to client application")
    static Response reauthenticate(Flow flow, String clientId, String clientSecret, String fullResponseUrl) {
        Response oidcAuth = startAuthenticationInSsoOidc(flow, clientId, fullResponseUrl)
        followRedirect(flow, oidcAuth)
        Map formParams = [loginChallenge: flow.loginChallenge,
                          _csrf         : flow.sessionService.cookies.get("__Host-XSRF-TOKEN")]
        Response reauthenticate = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullReauthenticateUrl, flow.sessionService.cookies, formParams)
        Response initLogin = followRedirectWithCookies(flow, reauthenticate, flow.ssoOidcService.cookies)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_authentication_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt(), initLogin.cookie("oauth2_authentication_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt()))
        Response followRedirect = followRedirect(flow, initLogin)
        Utils.setParameter(flow.sessionService.cookies, "__Host-AUTH", followRedirect.cookie("__Host-AUTH"))
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, followRedirect)
        return followRedirectsToClientApplication(flow, taraAuthentication, clientId, clientSecret, fullResponseUrl)
    }

    @Step("Initialize reauthentication sequence and follow redirects to client application after acr discrepancy")
    static Response reauthenticateAfterAcrDiscrepancy(Flow flow) {
        Map formParams = [loginChallenge: flow.loginChallenge,
                          _csrf         : flow.sessionService.cookies.get("__Host-XSRF-TOKEN")]
        Response reauthenticate = Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullReauthenticateUrl, flow.ssoOidcService.cookies, formParams)
        Response oidcAuth2 = followRedirect(flow, reauthenticate)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_authentication_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt(), oidcAuth2.cookie("oauth2_authentication_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt()))
        Response initLogin = followRedirectWithCookies(flow, oidcAuth2, flow.ssoOidcService.cookies)
        Utils.setParameter(flow.sessionService.cookies, "__Host-AUTH", initLogin.cookie("__Host-AUTH"))
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        return followRedirectsToClientApplication(flow, taraAuthentication, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
    }

    @Step("Verify session service response headers")
    static void verifyResponseHeaders(Response response) {
        assertThat(response.header("X-Frame-Options"), equalTo("DENY"))
        String policyString = "connect-src 'self'; default-src 'none'; font-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; block-all-mixed-content"
        assertThat(response.header("Content-Security-Policy"), equalTo(policyString))
        assertThat(response.header("Strict-Transport-Security"), anyOf(containsString("max-age=16070400"), containsString("max-age=31536000")))
        assertThat(response.header("Strict-Transport-Security"), containsString("includeSubDomains"))
        assertThat(response.header("Cache-Control"), equalTo("no-cache, no-store, max-age=0, must-revalidate"))
        assertThat(response.header("X-Content-Type-Options"), equalTo("nosniff"))
        assertThat(response.header("X-XSS-Protection"), equalTo("0"))
    }
}
