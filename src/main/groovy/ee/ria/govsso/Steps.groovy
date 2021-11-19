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

    @Step("Initialize authentication sequence in login service")
    static Response createLoginSession(Flow flow, Response response) {
        Response initLogin = followRedirect(flow, response)
        flow.taraLoginService.setSessionId(initLogin.getCookie("SESSION"))
        flow.taraLoginService.setLogin_locale(initLogin.getCookie("LOGIN_LOCALE"))
        if (initLogin.body().prettyPrint().contains("_csrf")) {
            flow.taraLoginService.setCsrf(initLogin.body().htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        }
        return initLogin
    }

    @Step("Start authentication in TARA and follow redirects")
    static Response startAuthenticationInTara(Flow flow, String url) {
        Response initOIDCServiceSession = Requests.getRequest(url)
        Utils.setParameter(flow.taraOidcService.cookies, "oauth2_authentication_csrf", initOIDCServiceSession.getCookie("oauth2_authentication_csrf"))
        Response initLogin = followRedirect(flow, initOIDCServiceSession)
        flow.taraLoginService.setSessionId(initLogin.getCookie("SESSION"))
        flow.taraLoginService.setLogin_locale(initLogin.getCookie("LOGIN_LOCALE"))
        if (initLogin.body().prettyPrint().contains("_csrf")) {
            flow.taraLoginService.setCsrf(initLogin.body().htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        }
        return initLogin
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
        Response acceptResponse = Requests.acceptAuthTara(flow, flow.taraLoginService.fullAuthAcceptUrl)
        Response oidcServiceResponse = Requests.followRedirectWithCookie(flow, acceptResponse.getHeader("location"), flow.taraOidcService.cookies)
        Utils.setParameter(flow.taraOidcService.cookies, "oauth2_consent_csrf", oidcServiceResponse.getCookie("oauth2_consent_csrf"))
        return Requests.getRequestWithSessionId(flow, oidcServiceResponse.getHeader("location"))
    }

    @Step("Authenticate with Smart-ID")
    static Response authenticateWithSid(Flow flow, String idCode) {
        Requests.startSidAuthentication(flow, idCode)
        pollSidResponse(flow)
        Response acceptResponse = Requests.acceptAuthTara(flow, flow.taraLoginService.fullAuthAcceptUrl)
        Response oidcServiceResponse = Requests.followRedirectWithCookie(flow, acceptResponse.getHeader("location"), flow.taraOidcService.cookies)
        Utils.setParameter(flow.taraOidcService.cookies, "oauth2_consent_csrf", oidcServiceResponse.getCookie("oauth2_consent_csrf"))
        return Requests.getRequestWithSessionId(flow, oidcServiceResponse.getHeader("location"))
    }

    @Step("Authenticate with ID-Card")
    static Response authenticateWithIdCard(Flow flow, String certificatePath) {
        String certificate = Utils.getCertificateAsString(certificatePath)

        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(headersMap, "XCLIENTCERTIFICATE", certificate)
        Requests.idCardAuthentication(flow, headersMap)
        Response acceptResponse = Requests.acceptAuthTara(flow, flow.taraLoginService.fullAuthAcceptUrl)

        Response oidcServiceResponse = Requests.followRedirectWithCookie(flow, acceptResponse.getHeader("location"), flow.taraOidcService.cookies)
        Utils.setParameter(flow.taraOidcService.cookies, "oauth2_consent_csrf", oidcServiceResponse.getCookie("oauth2_consent_csrf"))

        return Requests.getRequestWithSessionId(flow, oidcServiceResponse.getHeader("location"))
    }

    @Step("Authenticate with eIDAS")
    static Response authenticateWithEidas(Flow flow, String country, String username, String password, String loa) {
        LinkedHashMap<String, String> queryParamsMap = (LinkedHashMap) Collections.emptyMap()
        Utils.setParameter(queryParamsMap, "country", country)
        Utils.setParameter(queryParamsMap, "_csrf", flow.taraLoginService.csrf)
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookieMap, "SESSION", flow.taraLoginService.sessionId)
        Response initEidasAuthenticationSession = Requests.postRequestWithCookiesAndParams(flow, flow.taraLoginService.fullEidasInitUrl, cookieMap, queryParamsMap)
        flow.setNextEndpoint(initEidasAuthenticationSession.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))

        Response serviceProviderResponse = EidasSteps.eidasServiceProviderRequest(flow, flow.nextEndpoint, flow.relayState, flow.requestMessage)
        Response specificconnectorResponse = EidasSteps.eidasSpecificConnectorRequest(flow, serviceProviderResponse)
        Response colleagueResponse = EidasSteps.eidasColleagueRequest(flow, specificconnectorResponse)
        String endpointUrl = colleagueResponse.body().htmlPath().getString("**.find { it.@id == 'redirectForm' }.@action")
        String token = colleagueResponse.body().htmlPath().getString("**.find { it.@id == 'token' }.@value")
        Response eidasProxyResponse = EidasSteps.eidasProxyServiceRequest(flow, endpointUrl, token)

        Response initIdpResponse = EidasSteps.eidasIdpRequest(flow, eidasProxyResponse)
        Response authorizationRequest = EidasSteps.eidasIdpAuthorizationRequest(flow, initIdpResponse, username, password, loa)
        Response authorizationResponse = EidasSteps.eidasIdpAuthorizationResponse(flow, authorizationRequest)

        String binaryLightToken = authorizationResponse.body().htmlPath().get("**.find {it.@id == 'binaryLightToken'}.@value")
        Response consentResponse = EidasSteps.eidasConfirmConsent(flow, binaryLightToken)
        String endpointUrl2 = consentResponse.body().htmlPath().getString("**.find { it.@id == 'redirectForm' }.@action")
        String token2 = consentResponse.body().htmlPath().getString("**.find { it.@id == 'token' }.@value")
        Response eidasProxyResponse2 = EidasSteps.eidasProxyServiceRequest(flow, endpointUrl2, token2)
        Response colleagueResponse2 = EidasSteps.eidasColleagueResponse(flow, eidasProxyResponse2)
        Response authorizationResponse2 = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse2)
        Response redirectionResponse = EidasSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse2)
        flow.taraLoginService.setCsrf(redirectionResponse.body().htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        Response acceptResponse = Requests.acceptAuthTara(flow, flow.taraLoginService.fullAuthAcceptUrl)
        Response oidcServiceResponse = Requests.followRedirectWithCookie(flow, acceptResponse.getHeader("location"), flow.taraOidcService.cookies)
        Utils.setParameter(flow.taraOidcService.cookies, "oauth2_consent_csrf", oidcServiceResponse.getCookie("oauth2_consent_csrf"))
        return Requests.getRequestWithSessionId(flow, oidcServiceResponse.getHeader("location"))
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
        Utils.setParameter(formParamsMap, "_csrf", flow.taraLoginService.csrf)
        return Requests.postRequestWithCookiesAndParams(flow, flow.taraLoginService.fullConsentConfirmUrl, cookiesMap, formParamsMap)
    }

    @Step("Confirm or reject consent in GSSO")
    static Response submitConsentSso(Flow flow, boolean consentGiven) {
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookiesMap, "SESSION", flow.taraLoginService.sessionId)
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "consent_given", consentGiven)
 //       Utils.setParameter(formParamsMap, "_csrf", flow.csrf)
        return Requests.postRequestWithCookiesAndParams(flow, flow.sessionService.fullConsentConfirmUrl, cookiesMap, formParamsMap)
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
        assertThat(signedJWT.getJWTClaimsSet().getAudience().get(0), equalTo(flow.oidcClientA.clientId))
        assertThat(signedJWT.getJWTClaimsSet().getIssuer(), equalTo(flow.openIdServiceConfiguration.get("issuer")))
        Date date = new Date()
        assertThat("Expected current: " + date + " to be before exp: " + signedJWT.getJWTClaimsSet().getExpirationTime(), date.before(signedJWT.getJWTClaimsSet().getExpirationTime()), is(true))
//TODO: nbf not used in gsso?
//        assertThat("Expected current: " + date + " to be after nbf: " + signedJWT.getJWTClaimsSet().getNotBeforeTime(), date.after(signedJWT.getJWTClaimsSet().getNotBeforeTime()), is(true))
        if (!flow.getNonce().isEmpty()) {
            assertThat(signedJWT.getJWTClaimsSet().getStringClaim("nonce"), equalTo(flow.getNonce()))
        }
//TODO: state is not propagated to JWT in gsso?
//        assertThat(signedJWT.getJWTClaimsSet().getStringClaim("state"), equalTo(flow.getState()))
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
    static Response authenticateWithMidInTARA(Flow flow, String idCode, String phoneNo, Response response) {
        Steps.startAuthenticationInTara(flow, response.getHeader("location"))
        Response midAuthResponse = Steps.authenticateWithMid(flow, idCode, phoneNo)
// TODO: For SSO consent is never asked in TARA?
        return Requests.followRedirectWithCookie(flow, midAuthResponse.getHeader("location"), flow.taraOidcService.cookies)
    }

    @Step("Authenticate with SID in TARA")
    static Response authenticateWithSidInTARA(Flow flow, String idCode, Response response) {
        Steps.startAuthenticationInTara(flow, response.getHeader("location"))
        Response sidAuthResponse = Steps.authenticateWithSid(flow, idCode)
// TODO: For SSO consent is never asked in TARA?
        return Requests.followRedirectWithCookie(flow, sidAuthResponse.getHeader("location"), flow.taraOidcService.cookies)
    }

    @Step("Authenticate with ID-Card in TARA")
    static Response authenticateWithIdCardInTARA(Flow flow, Response response) {
        Steps.startAuthenticationInTara(flow, response.getHeader("location"))
        Response idCardAuthResponse = Steps.authenticateWithIdCard(flow, "src/test/resources/joeorg-auth.pem")
// TODO: For SSO consent is never asked in TARA?
        return Requests.followRedirectWithCookie(flow, idCardAuthResponse.getHeader("location"), flow.taraOidcService.cookies)
    }

    @Step("Authenticate with eIDAS in TARA")
    static Response authenticateWithEidasInTARA(Flow flow, String country, String username, String password, String loa, Response response) {
        Steps.startAuthenticationInTara(flow, response.getHeader("location"))
        Response eidasAuthResponse = Steps.authenticateWithEidas(flow, country, username, password, loa)
// TODO: For SSO consent is never asked in TARA?
        return Requests.followRedirectWithCookie(flow, eidasAuthResponse.getHeader("location"), flow.taraOidcService.cookies)
    }

    private static void addJsonAttachment(String name, String json) throws IOException {
        ObjectMapper mapper = new ObjectMapper()
        Object jsonObject = mapper.readValue(json, Object.class)
        String prettyJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject)
        Allure.addAttachment(name, "application/json", prettyJson, "json")
    }
}
