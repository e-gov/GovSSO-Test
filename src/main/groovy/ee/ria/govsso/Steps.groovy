package ee.ria.govsso

import com.nimbusds.jwt.SignedJWT
import io.qameta.allure.Step
import io.restassured.response.Response

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.anyOf
import static org.hamcrest.Matchers.containsString


class Steps {

    @Step("Initialize authentication sequence in SSO OIDC service with params")
    static Response startAuthenticationInSsoOidcWithParams(Flow flow, Map paramsMap) {
        Response oidcAuth = Requests.getRequestWithParams(flow, flow.ssoOidcService.fullAuthenticationRequestUrl, paramsMap)
        flow.setLoginChallenge(Utils.getParamValueFromResponseHeader(oidcAuth, "login_challenge"))
        return oidcAuth
    }

    @Step("Initialize authentication sequence in SSO OIDC service with params and origin headers")
    static Response startAuthenticationInSsoOidcWithParamsAndOrigin(Flow flow, Map paramsMap, String origin) {
        Response oidcAuth = Requests.getRequestWithParamsAndOrigin(flow, flow.ssoOidcService.fullAuthenticationRequestUrl, paramsMap, origin)
        flow.setLoginChallenge(Utils.getParamValueFromResponseHeader(oidcAuth, "login_challenge"))
        return oidcAuth
    }

    @Step("Initialize authentication sequence in OIDC service with defaults")
    static Response startAuthenticationInSsoOidc(Flow flow, clientId = flow.oidcClientA.clientId, responseUrl = flow.oidcClientA.fullResponseUrl) {
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, clientId, responseUrl)
        return startAuthenticationInSsoOidcWithParams(flow, paramsMap)
    }

    @Step("Initialize authentication sequence in OIDC service with origin")
    static Response startAuthenticationInSsoOidcWithOrigin(Flow flow, String clientId, String fullResponseUrl, String origin) {
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, clientId, fullResponseUrl)
        return startAuthenticationInSsoOidcWithParamsAndOrigin(flow, paramsMap, origin)
    }

    @Step("Initialize authentication sequence in OIDC service")
    static Response startAuthenticationInSsoOidcWithScope(Flow flow, String clientId, String clientSecret, String fullResponseUrl, String scope) {
        Map paramsMap = OpenIdUtils.getAuthorizationParametersWithScope(flow, clientId, clientSecret, fullResponseUrl, scope)
        return startAuthenticationInSsoOidcWithParams(flow, paramsMap)
    }

    @Step("Initialize session update sequence in OIDC service with defaults")
    static Response startSessionUpdateInSsoOidcWithDefaults(Flow flow, String idTokenHint, String origin) {
        Map paramsMap = OpenIdUtils.getSessionUpdateParametersWithDefaults(flow, idTokenHint)
        return startAuthenticationInSsoOidcWithParamsAndOrigin(flow, paramsMap, origin)
    }

    @Step("Initialize session in session service")
    static Response startSessionInSessionService(Flow flow, Response response) {
        Response initSession = followRedirect(flow, response)
        return initSession
    }

    @Step("Initialize session in session service with origin")
    static Response startSessionInSessionServiceWithOrigin(Flow flow, Response response, String origin) {
        Response initSession = followRedirectWithOrigin(flow, response, origin)
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

    @Step("Get identity token response with defaults")
    static Response getTokenResponseWithDefaults(Flow flow,
                                                 Response response,
                                                 String clientId = flow.oidcClientA.clientId,
                                                 String clientSecret = flow.oidcClientA.clientSecret,
                                                 String fullResponseUrl = flow.oidcClientA.fullResponseUrl,
                                                 String tokenType = "id_token") {
        String authorizationCode = Utils.getParamValueFromResponseHeader(response, "code")
        Response token = Requests.webTokenBasicRequest(flow, authorizationCode, clientId, clientSecret, fullResponseUrl)
        flow.setRefreshToken(token.jsonPath().get("refresh_token"))
        flow.setIdToken(token.jsonPath().get("id_token"))
        SignedJWT signedJWT = SignedJWT.parse(token.body.jsonPath().get(tokenType))
        Utils.addJsonAttachment("Header", signedJWT.header.toString())
        Utils.addJsonAttachment("Payload", signedJWT.JWTClaimsSet.toString())
        return token
    }

    @Step("Update session with defaults")
    static Response getSessionUpdateResponse(Flow flow) {
        return getSessionUpdateResponse(flow,
                flow.refreshToken,
                flow.oidcClientA.clientId,
                flow.oidcClientA.clientSecret)
    }

    @Step("Update session")
    static Response getSessionUpdateResponse(Flow flow, String refreshToken, String clientId, String clientSecret, String tokenType = "id_token") {
        Response tokenResponse = Requests.getSessionUpdateWebToken(flow, refreshToken, clientId, clientSecret)
        if (tokenResponse.statusCode != 200) {
            return tokenResponse
        } else {
            SignedJWT signedJWT = SignedJWT.parse(tokenResponse.body.jsonPath().get(tokenType))
            Utils.addJsonAttachment("Header", signedJWT.header.toString())
            Utils.addJsonAttachment("Payload", signedJWT.JWTClaimsSet.toString())
            return tokenResponse
        }
    }

    @Step("Update session with scope")
    static Response getSessionUpdateResponseWithScope(Flow flow, String scope) {
        Response tokenResponse = Requests.getSessionUpdateWebToken(flow, scope, flow.refreshToken, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret)
        if (tokenResponse.statusCode != 200) {
            return tokenResponse
        } else {
            SignedJWT signedJWT = SignedJWT.parse(tokenResponse.body.jsonPath().get("id_token"))
            Utils.addJsonAttachment("Header", signedJWT.header.toString())
            Utils.addJsonAttachment("Payload", signedJWT.JWTClaimsSet.toString())
            flow.setRefreshToken(tokenResponse.jsonPath().get("refresh_token"))
            return tokenResponse
        }
    }

    @Step("Follow redirects to token request")
    static Response followRedirectsToClientApplication(Flow flow,
                                                       Response response,
                                                       String clientId = flow.oidcClientA.clientId,
                                                       String clientSecret = flow.oidcClientA.clientSecret,
                                                       String fullResponseUrl = flow.oidcClientA.fullResponseUrl,
                                                       String tokenType = "id_token") {
        Response initLogin = followRedirect(flow, response)
        Response loginVerifier = followRedirect(flow, initLogin)
        flow.setConsentChallenge(Utils.getParamValueFromResponseHeader(loginVerifier, "consent_challenge"))
        Response initConsent = followRedirect(flow, loginVerifier)
        Response consentVerifier = followRedirect(flow, initConsent)
        return getTokenResponseWithDefaults(flow, consentVerifier, clientId, clientSecret, fullResponseUrl, tokenType)
    }

    @Step("Follow redirects to client application with existing session")
    static Response followRedirectsToClientApplicationWithExistingSession(Flow flow, Response response, String clientId, String clientSecret, String fullResponseUrl) {
        Response loginVerifier = followRedirect(flow, response)
        Response initConsent = followRedirect(flow, loginVerifier)
        Response consentVerifier = followRedirect(flow, initConsent)
        return getTokenResponseWithDefaults(flow, consentVerifier, clientId, clientSecret, fullResponseUrl)
    }

    @Step("Create initial session in GovSSO with ID-Card with client-A")
    static Response authenticateWithIdCardInGovSso(Flow flow) {
        Response oidcAuth = startAuthenticationInSsoOidc(flow)
        Response initLogin = startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        return followRedirectsToClientApplication(flow, taraAuthentication)
    }

    @Step("Create initial session in GovSSO with Client-B with scope")
    static Response authenticateInGovSsoWithScope(Flow flow, String scope = "openid representee.* representee_list") {
        Response oidcAuth = startAuthenticationInSsoOidcWithScope(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl, scope)
        Response initLogin = startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        return followRedirectsToClientApplication(flow, taraAuthentication, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl, "id_token")
    }

    @Step("Create initial session in GovSSO with ID-Card with client-A")
    static Response authenticateWithIdCardInGovSso(Flow flow,
                                                   String clientId,
                                                   String clientSecret,
                                                   String responseUrl,
                                                   String tokenType = "access_token") {
        Response oidcAuth = startAuthenticationInSsoOidc(flow, clientId, responseUrl)
        Response initLogin = startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        return followRedirectsToClientApplication(flow, taraAuthentication, clientId, clientSecret, responseUrl, tokenType)
    }

    @Step("Create initial session in GovSSO with ID-Card with client-A with custom ui_locales")
    static Response authenticateWithIdCardInGovSsoWithUiLocales(Flow flow, String uiLocales) {
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap << [ui_locales: uiLocales]
        Response oidcAuth = startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        return followRedirectsToClientApplication(flow, taraAuthentication)
    }

    @Step("Create initial session in GovSSO with eIDAS with client-A")
    static Response authenticateWithEidasInGovSso(Flow flow, String acrValue, String eidasLoa) {
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap << [acr_values: acrValue]
        Response oidcAuth = startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithEidasInTARA(flow, "CA", "xavi", "creus", eidasLoa, initLogin)
        return followRedirectsToClientApplication(flow, taraAuthentication)
    }

    @Step("Create initial session in GovSSO with eIDAS with client-A with custom ui_locales")
    static Response authenticateWithEidasInGovSsoWithUiLocales(Flow flow, String acrValue, String eidasLoa, uiLocales) {
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
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
                                  _csrf         : redirectResponse.body.htmlPath().get("**.find {it.@name == '_csrf'}.@value")]
                Response continueSession = Requests.postRequestWithParams(flow, flow.sessionService.fullContinueSessionUrl, formParams)
                return followRedirectsToClientApplicationWithExistingSession(flow, continueSession, clientId, clientSecret, responseUrl)
            }
        }
    }

    @Step("Use existing session to authenticate to another client with scope")
    static Response continueWithExistingSessionWithScope(Flow flow, String clientId, String clientSecret, String responseUrl, String scope) {
        Response oidcAuth = startAuthenticationInSsoOidcWithScope(flow, clientId, clientSecret, responseUrl, scope)
        Response initLogin = followRedirect(flow, oidcAuth)
        Map formParams = [loginChallenge: flow.loginChallenge,
                          _csrf         : initLogin.htmlPath().get("**.find {it.@name == '_csrf'}.@value")]
        Response continueSession = Requests.postRequestWithParams(flow, flow.sessionService.fullContinueSessionUrl, formParams)
        return followRedirectsToClientApplicationWithExistingSession(flow, continueSession, clientId, clientSecret, responseUrl)
    }

    @Step("Initialize logout with session in several GSSO clients and follow redirects")
    static Response logout(Flow flow, String idTokenHint, String logoutRedirectUri, String logoutTypeUrl) {
        Response oidcLogout = startLogout(flow, idTokenHint, logoutRedirectUri)
        Response initLogout = followRedirect(flow, oidcLogout)
        Map formParams = [logoutChallenge: flow.logoutChallenge,
                          _csrf          : initLogout.htmlPath().get("**.find {it.@name == '_csrf'}.@value")]
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
        Response initLogin1 = followRedirect(flow, oidcAuth)
        Map formParams = [loginChallenge: flow.loginChallenge,
                          _csrf         : initLogin1.htmlPath().get("**.find {it.@name == '_csrf'}.@value")]
        Response reauthenticate = Requests.postRequestWithParams(flow, flow.sessionService.fullReauthenticateUrl, formParams)
        Response initLogin2 = followRedirect(flow, reauthenticate)
        Response followRedirect = followRedirect(flow, initLogin2)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, followRedirect)
        return followRedirectsToClientApplication(flow, taraAuthentication, clientId, clientSecret, fullResponseUrl)
    }

    @Step("Initialize reauthentication sequence and follow redirects to client application after acr discrepancy")
    static Response reauthenticateAfterAcrDiscrepancy(Flow flow, Response response) {
        Response initLogin1 = followRedirect(flow, response)
        Map formParams = [loginChallenge: flow.loginChallenge,
                          _csrf         : initLogin1.htmlPath().get("**.find {it.@name == '_csrf'}.@value")]
        Response reauthenticate = Requests.postRequestWithParams(flow, flow.sessionService.fullReauthenticateUrl, formParams)
        Response oidcAuth2 = followRedirect(flow, reauthenticate)
        Response initLogin2 = followRedirect(flow, oidcAuth2)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin2)
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
