package ee.ria.govsso

import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.JOSEException
import com.nimbusds.jwt.SignedJWT
import io.qameta.allure.Allure
import io.qameta.allure.Step
import io.restassured.response.Response
import org.spockframework.lang.Wildcard

import java.text.ParseException

import static org.hamcrest.CoreMatchers.is
import static org.hamcrest.Matchers.anyOf
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.MatcherAssert.assertThat
import static org.junit.jupiter.api.Assertions.assertEquals

class Steps {

    @Step("Initialize authentication sequence in SSO OIDC service with params")
    static Response startAuthenticationInSsoOidcWithParams(Flow flow, Map<String, String> paramsMap) {
        Response initSession = Requests.getRequestWithParams(flow, flow.ssoOidcService.fullAuthenticationRequestUrl, paramsMap, Collections.emptyMap())
        String authCookie = initSession.getCookie("oauth2_authentication_csrf_insecure")
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_authentication_csrf_insecure", authCookie)
        String consentCookie = initSession.getCookie("oauth2_consent_csrf_insecure")
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_consent_csrf_insecure", consentCookie)
        flow.setLoginChallenge(Utils.getParamValueFromResponseHeader(initSession, "login_challenge"))
        return initSession
    }

    @Step("Initialize authentication sequence in OIDC service with defaults")
    static Response startAuthenticationInSsoOidc(Flow flow) {
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        return Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
    }

    @Step("Initialize session in session service with params")
    static Response startSessionInSessionService(Flow flow, Response response) {
        Response initSession = followRedirectWithSsoSessionCookies(flow, response, flow.sessionService.cookies)
        String authCookie = initSession.getCookie("oauth2_authentication_csrf")
        Utils.setParameter(flow.taraOidcService.cookies, "oauth2_authentication_csrf", authCookie)
        return initSession
    }

    @Step("Initialize authentication sequence in OIDC service with params")
    static Response startAuthenticationInTaraOidcWithParams(Flow flow, Map<String, String> paramsMap) {
        Response initSession = Requests.getRequestWithParams(flow, flow.taraOidcService.fullAuthenticationRequestUrl, paramsMap, Collections.emptyMap())
        String authCookie = initSession.getCookie("oauth2_authentication_csrf")
        Utils.setParameter(flow.taraOidcService.cookies, "oauth2_authentication_csrf", authCookie)
        flow.setLoginChallenge(Utils.getParamValueFromResponseHeader(initSession, "login_challenge"))
        return initSession
    }

    @Step("Initialize authentication sequence in OIDC service with defaults")
    static Response startAuthenticationInTaraOidc(Flow flow) {
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, flow.getOidcClient().getClientId(), flow.getOidcClient().getFullResponseUrl())
        Response initOIDCServiceSession = Steps.startAuthenticationInTaraOidcWithParams(flow, paramsMap)
        assertEquals(302, initOIDCServiceSession.statusCode(), "Correct HTTP status code is returned")
        return initOIDCServiceSession
    }

    @Step("Initialize taracallback in session service")
    static Response startTaracallback(Flow flow, Response response) {
        Response initCallback = followRedirectWithCookies(flow, response, flow.sessionService.cookies)
        return initCallback
    }

    @Step("Initialize authentication sequence in login service")
    static Response createLoginSession(Flow flow, Response response) {
        Response initLogin = followRedirect(flow, response)
        flow.taraLoginService.setSessionId(initLogin.getCookie("SESSION"))
        flow.setLogin_locale(initLogin.getCookie("LOGIN_LOCALE"))
        if (initLogin.body().prettyPrint().contains("_csrf")) {
            flow.setCsrf(initLogin.body().htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        }
        return initLogin
    }

    @Step("Start authentication in TARA and follow redirects")
    static Response startAuthenticationInTara(Flow flow, String scopeList = "openid", String login_locale = "et") {
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, scopeList, login_locale)
        Response initOIDCServiceSession = startAuthenticationInTaraOidcWithParams(flow, paramsMap)
        return createLoginSession(flow, initOIDCServiceSession)
    }

    @Step("Polling Mobile-ID authentication response")
    static Response pollMidResponse(Flow flow, long pollingIntevalMillis = 2000L) {
        int counter = 0
        Response response = null
        while (counter < 12) {
            sleep(pollingIntevalMillis)
            response = Requests.pollMid(flow)
            if (response.body().jsonPath().get("status") != "PENDING") {
                break
            }
            ++counter
        }
        return response
    }

    @Step("Authenticate with Mobile-ID")
    static Response authenticateWithMid(Flow flow, String idCode, String phoneNo) {
        Requests.startMidAuthentication(flow, idCode, phoneNo)
        pollMidResponse(flow)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.taraLoginService.fullAuthAcceptUrl)
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        return consentResponse
    }

    @Step("Authenticate with Smart-ID")
    static Response authenticateWithSid(Flow flow, String idCode) {
        initSidAuthSession(flow, flow.taraLoginService.sessionId, idCode, Collections.emptyMap())
        pollSidResponse(flow)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.taraLoginService.fullAuthAcceptUrl)
        Response oidcServiceResponse = getOAuthCookies(flow, acceptResponse)
        return followRedirectWithSessionId(flow, oidcServiceResponse)
    }

    @Step("Authenticate with ID-Card")
    static Response authenticateWithIdCard(Flow flow, String certificateFileName) {
        String certificate = Utils.getCertificateAsString(certificateFileName)
        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(headersMap, "XCLIENTCERTIFICATE", certificate)
        Requests.idCardAuthentication(flow, headersMap)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.taraLoginService.fullAuthAcceptUrl)
        Response oidcServiceResponse = getOAuthCookies(flow, acceptResponse)
        return followRedirectWithSessionId(flow, oidcServiceResponse)

    }

    @Step("Initialize Smart-ID authentication session")
    static Response initSidAuthSession(Flow flow, String sessionId
                                       , Object idCode
                                       , Map additionalParamsMap = Collections.emptyMap()) {
        LinkedHashMap<String, String> formParamsMap = (LinkedHashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "_csrf", flow.csrf)
        if (!(idCode instanceof Wildcard)) {
            Utils.setParameter(formParamsMap, "idCode", idCode)
        }
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookieMap, "SESSION", sessionId)
        Utils.setParameter(cookieMap, "LOGIN_LOCALE", flow.login_locale)
        return Requests.postRequestWithCookiesAndParams(flow, flow.taraLoginService.fullSidInitUrl, cookieMap, formParamsMap, additionalParamsMap)
    }

    @Step("Polling Smart-ID authentication response")
    static Response pollSidResponse(Flow flow, long pollingIntevalMillis = 2000L) {
        int counter = 0
        Response response = null
        while (counter < 20) {
            response = Requests.pollSid(flow)
            if (response.body().jsonPath().get("status") != "PENDING") {
                break
            }
            ++counter
            sleep(pollingIntevalMillis)
        }
        return response
    }


    @Step("Getting OAuth2 cookies")
    static Response getOAuthCookies(flow, Response response) {
        Response oidcServiceResponse = followRedirectWithCookies(flow, response, flow.taraOidcService.cookies)
        Utils.setParameter(flow.taraOidcService.cookies, "oauth2_consent_csrf", oidcServiceResponse.getCookie("oauth2_consent_csrf"))
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

    @Step("Confirm or reject consent in TARA")
    static Response submitConsentTara(Flow flow, boolean consentGiven) {
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookiesMap, "SESSION", flow.taraLoginService.sessionId)
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "consent_given", consentGiven)
        Utils.setParameter(formParamsMap, "_csrf", flow.csrf)
        return Requests.postRequestWithCookiesAndParams(flow, flow.taraLoginService.fullConsentConfirmUrl, cookiesMap, formParamsMap, Collections.emptyMap())
    }

    @Step("Confirm or reject consent in GSSO")
    static Response submitConsentSso(Flow flow, boolean consentGiven) {
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookiesMap, "SESSION", flow.taraLoginService.sessionId)
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "consent_given", consentGiven)
        Utils.setParameter(formParamsMap, "_csrf", flow.csrf)
        return Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullConsentConfirmUrl, cookiesMap, formParamsMap, Collections.emptyMap())
    }

    @Step("Confirm or reject consent and finish authentication process in TARA")
    static Response submitConsentAndFollowRedirectsTara(Flow flow, boolean consentGiven, Response consentResponse) {
        if (consentResponse.getStatusCode().toInteger() == 200) {
            consentResponse = submitConsentTara(flow, consentGiven)
        }
        return followRedirectWithCookies(flow, consentResponse, flow.taraOidcService.cookies)
    }

    @Step("Confirm or reject consent and finish authentication process in GSSO")
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

    @Step("verify token")
    static SignedJWT verifyTokenAndReturnSignedJwtObject(Flow flow, String token) throws ParseException, JOSEException, IOException {
        SignedJWT signedJWT = SignedJWT.parse(token)
        addJsonAttachment("Header", signedJWT.getHeader().toString())
        addJsonAttachment("Payload", signedJWT.getJWTClaimsSet().toString())
        try {
            Allure.link("View Token in jwt.io", new io.qameta.allure.model.Link().toString(),
                    "https://jwt.io/#debugger-io?token=" + token)
        } catch (Exception e) {
            //NullPointerException when running test from IntelliJ
        }
        assertThat("Token Signature is not valid!", OpenIdUtils.isTokenSignatureValid(flow.jwkSet, signedJWT), is(true))
        assertThat(signedJWT.getJWTClaimsSet().getAudience().get(0), equalTo(flow.oidcClient.clientId))
        assertThat(signedJWT.getJWTClaimsSet().getIssuer(), equalTo(flow.openIdServiceConfiguration.get("issuer")))
        Date date = new Date()
        assertThat("Expected current: " + date + " to be before exp: " + signedJWT.getJWTClaimsSet().getExpirationTime(), date.before(signedJWT.getJWTClaimsSet().getExpirationTime()), is(true))
        assertThat("Expected current: " + date + " to be after nbf: " + signedJWT.getJWTClaimsSet().getNotBeforeTime(), date.after(signedJWT.getJWTClaimsSet().getNotBeforeTime()), is(true))
        if (!flow.getNonce().isEmpty()) {
            assertThat(signedJWT.getJWTClaimsSet().getStringClaim("nonce"), equalTo(flow.getNonce()))
        }
        assertThat(signedJWT.getJWTClaimsSet().getStringClaim("state"), equalTo(flow.getState()))
        return signedJWT
    }

    @Step("verify response headers")
    static void verifyResponseHeaders(Response response) {
        assertThat(response.getHeader("X-Frame-Options"), equalTo("DENY"))
        String policyString = "connect-src 'self'; default-src 'none'; font-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; block-all-mixed-content"
        assertThat(response.getHeader("Content-Security-Policy"), equalTo(policyString))
        assertThat(response.getHeader("Strict-Transport-Security"), anyOf(containsString("max-age=16070400"), containsString("max-age=31536000")))
        assertThat(response.getHeader("Strict-Transport-Security"), containsString("includeSubDomains"))
        assertThat(response.getHeader("Cache-Control"), equalTo("no-cache, no-store, max-age=0, must-revalidate"))
        assertThat(response.getHeader("X-Content-Type-Options"), equalTo("nosniff"))
        assertThat(response.getHeader("X-XSS-Protection"), equalTo("1; mode=block"))
    }

    @Step("Authenticate with MID in TARA")
    static Response authenticateWithMidInTARA(Flow flow, String idCode, String phoneNo) {
        //TODO: This should be replaced with receiving URL from session service and following redirects. Enable automatic redirect following for this?
        Steps.startAuthenticationInTara(flow)

        //This should be ok as is
        Response midAuthResponse = Steps.authenticateWithMid(flow,idCode, phoneNo)

        //TODO: Enable automatic redirect following for this?
        return Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
    }

    @Step("Authenticate with SID in TARA")
    static Response authenticateWithSidInTARA(Flow flow, String idCode) {
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Response sidAuthResponse = Steps.authenticateWithSid(flow,idCode)
        return Steps.submitConsentAndFollowRedirects(flow, true, sidAuthResponse)
    }

    @Step("Authenticate with ID-Card in TARA")
    static Response authenticateWithIdCardInTARA(Flow flow) {
        String certificate = Utils.getCertificateAsString("src/test/resources/joeorg-auth.pem")
        Steps.startAuthenticationInTara(flow)
        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(headersMap, "XCLIENTCERTIFICATE", certificate)
        Requests.idCardAuthentication(flow, headersMap)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.taraLoginService.fullAuthAcceptUrl)
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)

        if (consentResponse.getStatusCode() == 200) {
            consentResponse = Steps.submitConsent(flow, true)
        }

        return Steps.followRedirectWithCookies(flow, consentResponse, flow.oidcService.cookies)
    }

    @Step("Authenticate with eIDAS in TARA")
    static Response authenticateWithEidasInTARA(Flow flow, String country, String username, String password, String loa) {
        //TODO: This should be replaced with receiving URL from session service and following redirects.
        Steps.startAuthenticationInTara(flow, "openid eidas")
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.taraLoginService.sessionId, country, Collections.emptyMap())
        flow.setNextEndpoint(initEidasAuthenticationSession.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, username, password, loa)
        Response authorizationResponse = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        Response redirectionResponse = EidasSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse)
        Response acceptResponse = EidasSteps.eidasAcceptAuthorizationResult(flow, redirectionResponse)
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        Response redirectResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        return Steps.submitConsentAndFollowRedirects(flow, true, redirectResponse)
    }

    private static void addJsonAttachment(String name, String json) throws IOException {
        ObjectMapper mapper = new ObjectMapper()
        Object jsonObject = mapper.readValue(json, Object.class)
        String prettyJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject)
        Allure.addAttachment(name, "application/json", prettyJson, "json")
    }
}
