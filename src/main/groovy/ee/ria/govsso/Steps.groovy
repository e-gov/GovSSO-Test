package ee.ria.govsso

import com.nimbusds.jwt.SignedJWT
import ee.ria.govsso.model.Client
import io.qameta.allure.Step
import io.restassured.response.Response

import java.text.ParseException

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
    static Response startAuthenticationInSsoOidc(Flow flow, Client client = ClientStore.clientA) {
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, client)
        return startAuthenticationInSsoOidcWithParams(flow, paramsMap)
    }

    @Step("Initialize authentication sequence in OIDC service with origin")
    static Response startAuthenticationInSsoOidcWithOrigin(Flow flow, Client client, String origin) {
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, client)
        return startAuthenticationInSsoOidcWithParamsAndOrigin(flow, paramsMap, origin)
    }

    @Step("Initialize authentication sequence in OIDC service")
    static Response startAuthenticationInSsoOidcWithScope(Flow flow, Client client, String scope) {
        Map paramsMap = OpenIdUtils.getAuthorizationParametersWithScope(flow, client, scope)
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

    @Step("Initialize logout sequence in OIDC with GET or POST")
    static Response startLogout(Flow flow, String idTokenHint, String logoutRedirectUri, boolean usePost = false) {
        Map params = OpenIdUtils.getLogoutParameters(idTokenHint, logoutRedirectUri)
        return logoutRequest(flow, params, logoutRedirectUri, usePost)
    }

    @Step("Initialize logout sequence in OIDC with GET or POST")
    static Response startLogoutWithUiLocales(Flow flow, String idTokenHint, String logoutRedirectUri, String uiLocales, boolean usePost = false) {
        Map params = OpenIdUtils.getLogoutParametersWithUiLocales(idTokenHint, logoutRedirectUri, uiLocales)
        return logoutRequest(flow, params, logoutRedirectUri, usePost)
    }

    @Step("Logout request in OIDC with GET or POST")
    static Response logoutRequest(Flow flow, Map logoutParams, String logoutRedirectUri, boolean usePost = false) {

        Response initLogout = usePost
                ? Requests.postRequestWithParams(flow, flow.ssoOidcService.fullLogoutUrl, logoutParams)
                : Requests.getRequestWithParams(flow, flow.ssoOidcService.fullLogoutUrl, logoutParams)

        if (initLogout.statusCode == 302 && initLogout.header("Location") != logoutRedirectUri) {
            flow.setLogoutChallenge(Utils.getParamValueFromResponseHeader(initLogout, "logout_challenge"))
        }
        return initLogout
    }

    @Step("Initialize logout sequence in OIDC with origin")
    static Response startLogoutWithOrigin(Flow flow, String idTokenHint, String logoutRedirectUri, String origin) {
        Map headersMap = [Origin: origin]
        Map queryParams = OpenIdUtils.getLogoutParameters(idTokenHint, logoutRedirectUri)
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
                                                 Client client = ClientStore.clientA,
                                                 String tokenType = "id_token") {
        String authorizationCode = Utils.getParamValueFromResponseHeader(response, "code")
        Response token = Requests.webTokenBasicRequest(flow, authorizationCode, client)
        flow.setRefreshToken(token.path("refresh_token"))
        flow.setIdToken(token.path("id_token"))
        attachTokenToReport(token.body.path(tokenType) as String, tokenType)
        return token
    }

    @Step("Update session with defaults")
    static Response getSessionUpdateResponse(Flow flow) {
        return getSessionUpdateResponse(flow, flow.refreshToken, ClientStore.clientA)
    }

    @Step("Update session")
    static Response getSessionUpdateResponse(Flow flow, String refreshToken, Client client, String tokenType = "id_token") {
        Response tokenResponse = Requests.getSessionUpdateWebToken(flow, refreshToken, client)
        if (tokenResponse.statusCode != 200) {
            return tokenResponse
        } else {
            attachTokenToReport(tokenResponse.body.path(tokenType) as String, tokenType)
            return tokenResponse
        }
    }

    @Step("Update session with scope")
    static Response getSessionUpdateResponseWithScope(Flow flow, String scope) {
        Response tokenResponse = Requests.getSessionUpdateWebToken(flow, scope, flow.refreshToken, ClientStore.clientB)
        if (tokenResponse.statusCode != 200) {
            return tokenResponse
        } else {
            attachTokenToReport(tokenResponse.body.path("id_token") as String, "id_token")
            flow.setRefreshToken(tokenResponse.path("refresh_token"))
            return tokenResponse
        }
    }

    @Step("Follow redirects to token request")
    static Response followRedirectsToClientApplication(Flow flow,
                                                       Response response,
                                                       Client client = ClientStore.clientA,
                                                       String tokenType = "id_token") {
        Response initLogin = followRedirect(flow, response)
        Response loginVerifier = followRedirect(flow, initLogin)
        flow.setConsentChallenge(Utils.getParamValueFromResponseHeader(loginVerifier, "consent_challenge"))
        Response initConsent = followRedirect(flow, loginVerifier)
        Response consentVerifier = followRedirect(flow, initConsent)
        return getTokenResponseWithDefaults(flow, consentVerifier, client, tokenType)
    }

    @Step("Follow redirects to client application with existing session")
    static Response followRedirectsToClientApplicationWithExistingSession(Flow flow, Response response, Client client) {
        Response loginVerifier = followRedirect(flow, response)
        Response initConsent = followRedirect(flow, loginVerifier)
        Response consentVerifier = followRedirect(flow, initConsent)
        return getTokenResponseWithDefaults(flow, consentVerifier, client)
    }

    @Step("Create initial session in GovSSO with Client-B with scope")
    static Response authenticateInGovSsoWithScope(Flow flow, String scope = "openid representee.* representee_list") {
        Response oidcAuth = startAuthenticationInSsoOidcWithScope(flow, ClientStore.clientB, scope)
        Response initLogin = startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        return followRedirectsToClientApplication(flow, taraAuthentication, ClientStore.clientB, "id_token")
    }

    @Step("Create initial session in GovSSO with ID-Card")
    static Response authenticateWithIdCardInGovSso(Flow flow,
                                                   Client client = ClientStore.clientA,
                                                   String tokenType = "id_token") {
        Response oidcAuth = startAuthenticationInSsoOidc(flow, client)
        Response initLogin = startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        return followRedirectsToClientApplication(flow, taraAuthentication, client, tokenType)
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
    static Response continueWithExistingSession(Flow flow, Client client = ClientStore.clientB) {
        Response oidcAuth = startAuthenticationInSsoOidc(flow, client)
        if (client.isUserConsentRequired != Boolean.TRUE) {
            // No consent screen
            return followRedirectsToClientApplication(flow, oidcAuth, client)
        }
        Response redirectResponse = followRedirect(flow, oidcAuth)
        if (redirectResponse.statusCode != 200) {
            return redirectResponse
        } else {
            Map formParams = [loginChallenge: flow.loginChallenge,
                              _csrf         : redirectResponse.body.htmlPath().get("**.find {it.@name == '_csrf'}.@value")]
            Response continueSession = Requests.postRequestWithParams(flow, flow.sessionService.fullContinueSessionUrl, formParams)
            return followRedirectsToClientApplicationWithExistingSession(flow, continueSession, client)
        }
    }

    @Step("Use existing session to authenticate to another client with scope")
    static Response continueWithExistingSessionWithScope(Flow flow, Client client, String scope) {
        Response oidcAuth = startAuthenticationInSsoOidcWithScope(flow, client, scope)
        Response initLogin = followRedirect(flow, oidcAuth)
        Map formParams = [loginChallenge: flow.loginChallenge,
                          _csrf         : initLogin.htmlPath().get("**.find {it.@name == '_csrf'}.@value")]
        Response continueSession = Requests.postRequestWithParams(flow, flow.sessionService.fullContinueSessionUrl, formParams)
        return followRedirectsToClientApplicationWithExistingSession(flow, continueSession, client)
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
        Response oidcLogout = startLogout(flow, flow.idToken, ClientStore.clientA.postLogoutRedirectUri)
        Response initLogout = followRedirect(flow, oidcLogout)
        return followRedirect(flow, initLogout)
    }

    @Step("Initialize reauthentication sequence and follow redirects to client application")
    static Response reauthenticate(Flow flow, Client client) {
        Response oidcAuth = startAuthenticationInSsoOidc(flow, client)
        Response initLogin1 = followRedirect(flow, oidcAuth)
        Map formParams = [loginChallenge: flow.loginChallenge,
                          _csrf         : initLogin1.htmlPath().get("**.find {it.@name == '_csrf'}.@value")]
        Response reauthenticate = Requests.postRequestWithParams(flow, flow.sessionService.fullReauthenticateUrl, formParams)
        Response initLogin2 = followRedirect(flow, reauthenticate)
        Response followRedirect = followRedirect(flow, initLogin2)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, followRedirect)
        return followRedirectsToClientApplication(flow, taraAuthentication, client)
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
        return followRedirectsToClientApplication(flow, taraAuthentication, ClientStore.clientB)
    }

    private static void attachTokenToReport(String tokenValue, String tokenName) {
        if (tokenValue == null) {
            return
        }
        try {
            SignedJWT signedJWT = SignedJWT.parse(tokenValue)
            Utils.addJsonAttachment("Header", signedJWT.header.toString())
            Utils.addJsonAttachment("Payload", signedJWT.JWTClaimsSet.toString())
        } catch (ParseException ignored) {
            Utils.addJsonAttachment(tokenName, tokenValue)
        }
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
