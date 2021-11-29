package ee.ria.govsso

import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.JOSEException
import com.nimbusds.jwt.SignedJWT
import io.qameta.allure.Allure
import io.qameta.allure.Step
import io.restassured.response.Response

import java.text.ParseException

import static org.hamcrest.CoreMatchers.is
import static org.hamcrest.Matchers.anyOf
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.MatcherAssert.assertThat

class Steps {

    @Step("Initialize authentication sequence in SSO OIDC service with params")
    static Response startAuthenticationInSsoOidcWithParams(Flow flow, Map<String, String> paramsMap) {
        Response initSession = Requests.getRequestWithParams(flow, flow.ssoOidcService.fullAuthenticationRequestUrl, paramsMap, Collections.emptyMap())
        String authCookie = initSession.getCookie("oauth2_authentication_csrf_insecure")
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_authentication_csrf_insecure", authCookie)
        flow.setLoginChallenge(Utils.getParamValueFromResponseHeader(initSession, "login_challenge"))
        return initSession
    }

    @Step("Initialize authentication sequence in OIDC service with defaults")
    static Response startAuthenticationInSsoOidc(Flow flow) {
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
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
        String sessionCookie = response.getCookie("SESSION")
        Utils.setParameter(flow.sessionService.cookies, "SESSION", sessionCookie)
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

    @Step("Get identity token")
    static Response getIdentityTokenResponse(Flow flow, Response response) {
        String authorizationCode = Utils.getParamValueFromResponseHeader(response, "code")
        return Requests.getWebToken(flow, authorizationCode)
    }

    @Step("Follow redirects to client application")
    static Response followRedirectsToClientApplication (Flow flow, Response authenticationFinishedResponse) {
        Response sessionServiceResponse = Steps.followRedirectWithCookies(flow, authenticationFinishedResponse, flow.ssoOidcService.cookies)
        Response oidcServiceResponse = Steps.followRedirectWithCookies(flow, sessionServiceResponse, flow.ssoOidcService.cookies)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_consent_csrf_insecure", oidcServiceResponse.getCookie("oauth2_consent_csrf_insecure"))
        Response sessionServiceConsentResponse = Steps.followRedirectWithCookies(flow, oidcServiceResponse, flow.ssoOidcService.cookies)
        return Steps.followRedirectWithCookies(flow, sessionServiceConsentResponse, flow.ssoOidcService.cookies)
    }


}
