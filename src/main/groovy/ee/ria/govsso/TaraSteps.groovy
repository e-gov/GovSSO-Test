package ee.ria.govsso

import io.qameta.allure.Step
import io.restassured.response.Response

class TaraSteps {

    @Step("Eidas service provider request")
    static Response eidasServiceProviderRequest(Flow flow, String url, String relayState, String samlRequest, String country = "CA") {
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "country", country)
        Utils.setParameter(formParamsMap, "RelayState", relayState)
        Utils.setParameter(formParamsMap, "SAMLRequest", samlRequest)
        return Requests.postRequestWithParams(flow, url, formParamsMap)
    }

    @Step("Eidas specific connector request")
    static Response eidasSpecificConnectorRequest(Flow flow, Response response) {
        String specificConnectorUrl = response.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action")
        String token = response.body().htmlPath().getString("**.find { input -> input.@name == 'token' }.@value")
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "token", token)
        Response serviceProviderResponse = Requests.postRequestWithParams(flow, specificConnectorUrl, formParamsMap)
        return serviceProviderResponse
    }

    @Step("Eidas colleague request")
    static Response eidasColleagueRequest(Flow flow, Response response) {
        String colleagueRequestUrl = response.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action")
        String samlRequest = response.body().htmlPath().getString("**.find { input -> input.@id == 'noScriptSAMLRequest' }.@value")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "SAMLRequest", samlRequest)
        Response colleagueResponse = Requests.postRequestWithParams(flow, colleagueRequestUrl, paramsMap)
        return colleagueResponse
    }

    @Step("Eidas proxy service request")
    static Response eidasProxyServiceRequest(Flow flow, String endpointUrl, String token) {
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "token", token)
        Response proxyServiceResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap)
        return proxyServiceResponse
    }

    @Step("Eidas User gives consent for redirection to iDP")
    static Response eidasIdpRequest(Flow flow, Response response) {
        String endpointUrl = response.body().htmlPath().getString("**.find { it.@name == 'redirectForm' }.@action")
        String smsspRequest = response.body().htmlPath().getString("**.find { input -> input.@id == 'SMSSPRequest' }.@value")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "SMSSPRequest", smsspRequest)
        return Requests.postRequestWithParams(flow, endpointUrl, paramsMap)
    }

    @Step("Eidas iDP authorization request")
    static Response eidasIdpAuthorizationRequest(flow, Response response, String idpUsername, idpPassword, String eidasloa) {
        String callbackUrl = response.body().htmlPath().getString("**.find { it.@name == 'callback' }.@value")
        String smsspToken = response.body().htmlPath().get("**.find {it.@name == 'smsspToken'}.@value")
        String smsspTokenRequestJson = response.body().htmlPath().get("**.find {it.@id == 'jSonRequestDecoded'}")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "smsspToken", smsspToken)
        Utils.setParameter(paramsMap, "username", idpUsername)
        Utils.setParameter(paramsMap, "password", idpPassword)
        Utils.setParameter(paramsMap, "eidasloa", eidasloa)
        Utils.setParameter(paramsMap, "eidasnameid", "persistent")
        Utils.setParameter(paramsMap, "callback", callbackUrl)
        Utils.setParameter(paramsMap, "jSonRequestDecoded", smsspTokenRequestJson)
        Response authorizationRequest =  Requests.postRequestWithParams(flow, flow.foreignIdpProvider.fullResponseUrl, paramsMap)
        return authorizationRequest
    }

    @Step("Eidas iDP authorization response")
    static Response eidasIdpAuthorizationResponse(Flow flow, Response response) {
        String endpointUrl = response.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String smsspTokenResponse = response.body().htmlPath().get("**.find {it.@id == 'SMSSPResponseNoJS'}.@value")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "SMSSPResponse", smsspTokenResponse)
        Response authorizationResponse =  Requests.postRequestWithParams(flow, endpointUrl, paramsMap)
        return authorizationResponse
    }

    @Step("Eidas confirm consent")
    static Response eidasConfirmConsent(Flow flow, String binaryLightToken) {
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "binaryLightToken", binaryLightToken)
        Response consentResponse =  Requests.postRequestWithParams(flow, flow.foreignProxyService.fullConsentUrl, paramsMap)
        return consentResponse
    }

    @Step("Eidas colleague response")
    static Response eidasColleagueResponse(Flow flow, Response response) {
        String endpointUrl = response.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String samlResponse = response.body().htmlPath().get("**.find {it.@name == 'SAMLResponse'}.@value")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "SAMLResponse", samlResponse)
        Response colleagueResponse =  Requests.postRequestWithParams(flow, endpointUrl, paramsMap)
        return colleagueResponse
    }

    @Step("Eidas authorization response")
    static Response getAuthorizationResponseFromEidas(Flow flow, Response response) {
        String endpointUrl = response.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String lightToken = response.body().htmlPath().get("**.find {it.@id == 'token'}.@value")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "token", lightToken)
        Response authorizationResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap)
        return authorizationResponse
    }

    @Step("Eidas redirect authorization response to service provider")
    static Response eidasRedirectAuthorizationResponse(Flow flow, Response response) {
        String endpointUrl = response.body().htmlPath().get("**.find {it.@method == 'post'}.@action")
        String samlResponse = response.body().htmlPath().get("**.find {it.@name == 'SAMLResponse'}.@value")
        String relayState = response.body().htmlPath().get("**.find {it.@name == 'RelayState'}.@value")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "SAMLResponse" , samlResponse)
        Utils.setParameter(paramsMap, "RelayState", relayState)
        Response redirectionResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap)
        return redirectionResponse
    }

    @Step("Start authentication in TARA and follow redirects")
    static Response startAuthenticationInTara(Flow flow, String url) {
        Response initOIDCServiceSession = Requests.getRequest(url)
        Utils.setParameter(flow.taraService.cookies, "oauth2_authentication_csrf", initOIDCServiceSession.getCookie("oauth2_authentication_csrf"))
        Response initLogin = Steps.followRedirect(flow, initOIDCServiceSession)
        flow.taraService.setSessionId(initLogin.getCookie("SESSION"))
        flow.taraService.setLogin_locale(initLogin.getCookie("LOGIN_LOCALE"))
        if (initLogin.body().prettyPrint().contains("_csrf")) {
            flow.taraService.setCsrf(initLogin.body().htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        }
        return initLogin
    }

    @Step("Initialize authentication sequence in login service")
    static Response createLoginSession(Flow flow, Response response) {
        Response initLogin = Steps.followRedirect(flow, response)
        flow.taraService.setSessionId(initLogin.getCookie("SESSION"))
        flow.taraService.setLogin_locale(initLogin.getCookie("LOGIN_LOCALE"))
        if (initLogin.body().prettyPrint().contains("_csrf")) {
            flow.taraService.setCsrf(initLogin.body().htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
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
        Response acceptResponse = Requests.acceptAuthTara(flow, flow.taraService.fullAuthAcceptUrl)
        Response oidcServiceResponse = Requests.followRedirectWithCookie(flow, acceptResponse.getHeader("location"), flow.taraService.cookies)
        Utils.setParameter(flow.taraService.cookies, "oauth2_consent_csrf", oidcServiceResponse.getCookie("oauth2_consent_csrf"))
        return Requests.getRequestWithSessionId(flow, oidcServiceResponse.getHeader("location"))
    }

    @Step("Authenticate with Smart-ID")
    static Response authenticateWithSid(Flow flow, String idCode) {
        Requests.startSidAuthentication(flow, idCode)
        pollSidResponse(flow)
        Response acceptResponse = Requests.acceptAuthTara(flow, flow.taraService.fullAuthAcceptUrl)
        Response oidcServiceResponse = Requests.followRedirectWithCookie(flow, acceptResponse.getHeader("location"), flow.taraService.cookies)
        Utils.setParameter(flow.taraService.cookies, "oauth2_consent_csrf", oidcServiceResponse.getCookie("oauth2_consent_csrf"))
        return Requests.getRequestWithSessionId(flow, oidcServiceResponse.getHeader("location"))
    }

    @Step("Authenticate with ID-Card")
    static Response authenticateWithIdCard(Flow flow, String certificatePath) {
        String certificate = Utils.getCertificateAsString(certificatePath)

        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(headersMap, "XCLIENTCERTIFICATE", certificate)
        Requests.idCardAuthentication(flow, headersMap)
        Response acceptResponse = Requests.acceptAuthTara(flow, flow.taraService.fullAuthAcceptUrl)

        Response oidcServiceResponse = Requests.followRedirectWithCookie(flow, acceptResponse.getHeader("location"), flow.taraService.cookies)
        Utils.setParameter(flow.taraService.cookies, "oauth2_consent_csrf", oidcServiceResponse.getCookie("oauth2_consent_csrf"))

        return Requests.getRequestWithSessionId(flow, oidcServiceResponse.getHeader("location"))
    }

    @Step("Authenticate with eIDAS")
    static Response authenticateWithEidas(Flow flow, String country, String username, String password, String loa) {
        LinkedHashMap<String, String> queryParamsMap = (LinkedHashMap) Collections.emptyMap()
        Utils.setParameter(queryParamsMap, "country", country)
        Utils.setParameter(queryParamsMap, "_csrf", flow.taraService.csrf)
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookieMap, "SESSION", flow.taraService.sessionId)
        Response initEidasAuthenticationSession = Requests.postRequestWithCookiesAndParams(flow, flow.taraService.fullEidasInitUrl, cookieMap, queryParamsMap)
        flow.setNextEndpoint(initEidasAuthenticationSession.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))

        Response serviceProviderResponse = TaraSteps.eidasServiceProviderRequest(flow, flow.nextEndpoint, flow.relayState, flow.requestMessage)
        Response specificconnectorResponse = TaraSteps.eidasSpecificConnectorRequest(flow, serviceProviderResponse)
        Response colleagueResponse = TaraSteps.eidasColleagueRequest(flow, specificconnectorResponse)
        String endpointUrl = colleagueResponse.body().htmlPath().getString("**.find { it.@id == 'redirectForm' }.@action")
        String token = colleagueResponse.body().htmlPath().getString("**.find { it.@id == 'token' }.@value")
        Response eidasProxyResponse = TaraSteps.eidasProxyServiceRequest(flow, endpointUrl, token)

        Response initIdpResponse = TaraSteps.eidasIdpRequest(flow, eidasProxyResponse)
        Response authorizationRequest = TaraSteps.eidasIdpAuthorizationRequest(flow, initIdpResponse, username, password, loa)
        Response authorizationResponse = TaraSteps.eidasIdpAuthorizationResponse(flow, authorizationRequest)

        String binaryLightToken = authorizationResponse.body().htmlPath().get("**.find {it.@id == 'binaryLightToken'}.@value")
        Response consentResponse = TaraSteps.eidasConfirmConsent(flow, binaryLightToken)
        String endpointUrl2 = consentResponse.body().htmlPath().getString("**.find { it.@id == 'redirectForm' }.@action")
        String token2 = consentResponse.body().htmlPath().getString("**.find { it.@id == 'token' }.@value")
        Response eidasProxyResponse2 = TaraSteps.eidasProxyServiceRequest(flow, endpointUrl2, token2)
        Response colleagueResponse2 = TaraSteps.eidasColleagueResponse(flow, eidasProxyResponse2)
        Response authorizationResponse2 = TaraSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse2)
        Response redirectionResponse = TaraSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse2)
        flow.taraService.setCsrf(redirectionResponse.body().htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        Response acceptResponse = Requests.acceptAuthTara(flow, flow.taraService.fullAuthAcceptUrl)
        Response oidcServiceResponse = Requests.followRedirectWithCookie(flow, acceptResponse.getHeader("location"), flow.taraService.cookies)
        Utils.setParameter(flow.taraService.cookies, "oauth2_consent_csrf", oidcServiceResponse.getCookie("oauth2_consent_csrf"))
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

    @Step("Confirm or reject consent in TARA")
    static Response submitConsentTara(Flow flow, boolean consentGiven) {
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookiesMap, "SESSION", flow.taraService.sessionId)
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "consent_given", consentGiven)
        Utils.setParameter(formParamsMap, "_csrf", flow.taraService.csrf)
        return Requests.postRequestWithCookiesAndParams(flow, flow.taraService.fullConsentConfirmUrl, cookiesMap, formParamsMap)
    }

    @Step("Authenticate with MID in TARA")
    static Response authenticateWithMidInTARA(Flow flow, String idCode, String phoneNo, Response response) {
        startAuthenticationInTara(flow, response.getHeader("location"))
        Response midAuthResponse = authenticateWithMid(flow, idCode, phoneNo)
// TODO: For SSO consent is never asked in TARA?
        return Requests.followRedirectWithCookie(flow, midAuthResponse.getHeader("location"), flow.taraService.cookies)
    }

    @Step("Authenticate with SID in TARA")
    static Response authenticateWithSidInTARA(Flow flow, String idCode, Response response) {
        startAuthenticationInTara(flow, response.getHeader("location"))
        Response sidAuthResponse = authenticateWithSid(flow, idCode)
// TODO: For SSO consent is never asked in TARA?
        return Requests.followRedirectWithCookie(flow, sidAuthResponse.getHeader("location"), flow.taraService.cookies)
    }

    @Step("Authenticate with ID-Card in TARA")
    static Response authenticateWithIdCardInTARA(Flow flow, Response response) {
        startAuthenticationInTara(flow, response.getHeader("location"))
        Response idCardAuthResponse = authenticateWithIdCard(flow, "src/test/resources/joeorg-auth.pem")
// TODO: For SSO consent is never asked in TARA?
        return Requests.followRedirectWithCookie(flow, idCardAuthResponse.getHeader("location"), flow.taraService.cookies)
    }

    @Step("Authenticate with eIDAS in TARA")
    static Response authenticateWithEidasInTARA(Flow flow, String country, String username, String password, String loa, Response response) {
        startAuthenticationInTara(flow, response.getHeader("location"))
        Response eidasAuthResponse = authenticateWithEidas(flow, country, username, password, loa)
// TODO: For SSO consent is never asked in TARA?
        return Requests.followRedirectWithCookie(flow, eidasAuthResponse.getHeader("location"), flow.taraService.cookies)
    }

}
