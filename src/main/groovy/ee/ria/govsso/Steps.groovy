package ee.ria.govsso


import com.nimbusds.jwt.SignedJWT
import io.qameta.allure.Step
import io.restassured.response.Response

class Steps {

    @Step("Initialize authentication sequence in SSO OIDC service with params")
    static Response startAuthenticationInSsoOidcWithParams(Flow flow, Map<String, String> paramsMap) {
        Response initSession = Requests.getRequestWithCookiesAndParams(flow, flow.ssoOidcService.fullAuthenticationRequestUrl, flow.ssoOidcService.getCookies(), paramsMap, Collections.emptyMap())
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_authentication_csrf_insecure", initSession.getCookie("oauth2_authentication_csrf_insecure"))
        flow.setLoginChallenge(Utils.getParamValueFromResponseHeader(initSession, "login_challenge"))
        return initSession
    }

    @Step("Initialize authentication sequence in OIDC service with defaults")
    static Response startAuthenticationInSsoOidcWithDefaults(Flow flow) {
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        return Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
    }

    @Step("Initialize authentication sequence in OIDC service")
    static Response startAuthenticationInSsoOidc(Flow flow, String clientId, String fullResponseUrl) {
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, clientId, fullResponseUrl)
        return Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
    }

    @Step("Initialize session in session service with params")
    static Response startSessionInSessionService(Flow flow, Response response) {
        Response initSession = followRedirectWithCookies(flow, response, flow.ssoOidcService.cookies)
        return initSession
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
        Utils.setParameter(flow.sessionService.cookies, "SESSION", response.getCookie("SESSION"))
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
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookiesMap, "SESSION", flow.taraService.sessionId)
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "consent_given", consentGiven)
 //       Utils.setParameter(formParamsMap, "_csrf", flow.csrf)
        return Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullConsentConfirmUrl, cookiesMap, formParamsMap)
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
    static Response followRedirectsToClientApplication (Flow flow, Response authenticationFinishedResponse) {
        Response sessionServiceResponse = Steps.followRedirectWithCookies(flow, authenticationFinishedResponse, flow.ssoOidcService.cookies)
        Response oidcServiceResponse = Steps.followRedirectWithCookies(flow, sessionServiceResponse, flow.ssoOidcService.cookies)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_consent_csrf_insecure", oidcServiceResponse.getCookie("oauth2_consent_csrf_insecure"))
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_authentication_session_insecure", oidcServiceResponse.getCookie("oauth2_authentication_session_insecure"))
        Response sessionServiceConsentResponse = Steps.followRedirectWithCookies(flow, oidcServiceResponse, flow.ssoOidcService.cookies)
        return Steps.followRedirectWithCookies(flow, sessionServiceConsentResponse, flow.ssoOidcService.cookies)
    }

    @Step("Follow redirects to client application with existing session")
    static Response followRedirectsToClientApplicationWithExistingSession (Flow flow, Response response, String clientId, String clientSecret, String fullResponseUrl) {
        Response oidcServiceResponse1 = Steps.followRedirect(flow, response)
        Response consentResponse = Steps.followRedirect(flow, oidcServiceResponse1)
        Response oidcServiceResponse2 = Steps.followRedirect(flow, consentResponse)
        return Steps.getIdentityTokenResponse(flow, oidcServiceResponse2, clientId, clientSecret, fullResponseUrl)
    }

    @Step("Create initial session in GOVSSO with Mobile-ID in Client-A")
    static Response authenticateWithMidInGovsso(flow) {
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response sessionServiceRedirectToTaraResponse = Steps.startSessionInSessionService(flow, oidcServiceInitResponse)
        Response authenticationFinishedResponse = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", sessionServiceRedirectToTaraResponse)
        Response oidcServiceConsentResponse = Steps.followRedirectsToClientApplication(flow, authenticationFinishedResponse)
        return Steps.getIdentityTokenResponseWithDefaults(flow, oidcServiceConsentResponse)
    }
}
