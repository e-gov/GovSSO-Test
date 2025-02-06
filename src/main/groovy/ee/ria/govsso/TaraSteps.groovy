package ee.ria.govsso

import io.qameta.allure.Step
import io.restassured.response.Response
import org.json.JSONObject

import static io.restassured.RestAssured.given

class TaraSteps {

    @Step("Eidas service provider request")
    static Response eidasServiceProviderRequest(Flow flow, String url, String relayState, String samlRequest, String country = "CA") {
        Map formParamsMap = [country    : country,
                             RelayState : relayState,
                             SAMLRequest: samlRequest]
        return Requests.postRequestWithParams(flow, url, formParamsMap)
    }

    @Step("Eidas specific connector request")
    static Response eidasSpecificConnectorRequest(Flow flow, Response response) {
        String specificConnectorUrl = response.body.htmlPath().getString("**.find { form -> form.@method == 'post' }.@action")
        String token = response.body.htmlPath().getString("**.find { input -> input.@name == 'token' }.@value")
        Map formParamsMap = [token: token]
        Response serviceProviderResponse = Requests.postRequestWithParams(flow, specificConnectorUrl, formParamsMap)
        return serviceProviderResponse
    }

    @Step("Eidas colleague request")
    static Response eidasColleagueRequest(Flow flow, Response response) {
        String colleagueRequestUrl = response.body.htmlPath().getString("**.find { form -> form.@method == 'post' }.@action")
        String samlRequest = response.body.htmlPath().getString("**.find { input -> input.@id == 'noScriptSAMLRequest' }.@value")
        Map paramsMap = [SAMLRequest: samlRequest]
        Response colleagueResponse = Requests.postRequestWithParams(flow, colleagueRequestUrl, paramsMap)
        return colleagueResponse
    }

    @Step("Eidas proxy service request")
    static Response eidasProxyServiceRequest(Flow flow, String endpointUrl, String token) {
        Map paramsMap = [token: token]
        Response proxyServiceResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap)
        return proxyServiceResponse
    }

    @Step("Eidas User gives consent for redirection to iDP")
    static Response eidasIdpRequest(Flow flow, Response response) {
        String endpointUrl = response.body.htmlPath().getString("**.find { it.@name == 'redirectForm' }.@action")
        String smsspRequest = response.body.htmlPath().getString("**.find { input -> input.@id == 'SMSSPRequest' }.@value")
        Map paramsMap = [SMSSPRequest: smsspRequest]
        return Requests.postRequestWithParams(flow, endpointUrl, paramsMap)
    }

    @Step("Eidas iDP authorization request")
    static Response eidasIdpAuthorizationRequest(flow, Response response, String idpUsername, idpPassword, String eidasloa) {
        String callbackUrl = response.body.htmlPath().getString("**.find { it.@name == 'callback' }.@value")
        String smsspToken = response.body.htmlPath().get("**.find {it.@name == 'smsspToken'}.@value")
        String smsspTokenRequestJson = response.body.htmlPath().get("**.find {it.@id == 'jSonRequestDecoded'}")
        Map paramsMap = [smsspToken        : smsspToken,
                         username          : idpUsername,
                         password          : idpPassword,
                         eidasloa          : eidasloa,
                         eidasnameid       : "persistent",
                         callback          : callbackUrl,
                         jSonRequestDecoded: smsspTokenRequestJson]
        Response authorizationRequest = Requests.postRequestWithParams(flow, flow.foreignIdpProvider.fullResponseUrl, paramsMap)
        return authorizationRequest
    }

    @Step("Eidas iDP authorization response")
    static Response eidasIdpAuthorizationResponse(Flow flow, Response response) {
        String endpointUrl = response.body.htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String smsspTokenResponse = response.body.htmlPath().get("**.find {it.@id == 'SMSSPResponseNoJS'}.@value")
        Map paramsMap = [SMSSPResponse: smsspTokenResponse]
        Response authorizationResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap)
        return authorizationResponse
    }

    @Step("Eidas confirm consent")
    static Response eidasConfirmConsent(Flow flow, String binaryLightToken) {
        Map paramsMap = [binaryLightToken: binaryLightToken]
        Response consentResponse = Requests.postRequestWithParams(flow, flow.foreignProxyService.fullConsentUrl, paramsMap)
        return consentResponse
    }

    @Step("Eidas colleague response")
    static Response eidasColleagueResponse(Flow flow, Response response) {
        String endpointUrl = response.body.htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String samlResponse = response.body.htmlPath().get("**.find {it.@name == 'SAMLResponse'}.@value")
        Map paramsMap = [SAMLResponse: samlResponse]
        Response colleagueResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap)
        return colleagueResponse
    }

    @Step("Eidas authorization response")
    static Response getAuthorizationResponseFromEidas(Flow flow, Response response) {
        String endpointUrl = response.body.htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String lightToken = response.body.htmlPath().get("**.find {it.@id == 'token'}.@value")
        Map paramsMap = [token: lightToken]
        Response authorizationResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap)
        return authorizationResponse
    }

    @Step("Eidas redirect authorization response to service provider")
    static Response eidasRedirectAuthorizationResponse(Flow flow, Response response) {
        String endpointUrl = response.body.htmlPath().get("**.find {it.@method == 'post'}.@action")
        String samlResponse = response.body.htmlPath().get("**.find {it.@name == 'SAMLResponse'}.@value")
        String relayState = response.body.htmlPath().get("**.find {it.@name == 'RelayState'}.@value")
        Map paramsMap = [SAMLResponse: samlResponse,
                         RelayState  : relayState]
        Response redirectionResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap)
        return redirectionResponse
    }

    @Step("Start authentication in TARA and follow redirects")
    static Response startAuthenticationInTara(Flow flow, String url) {
        Response initOIDCServiceSession = Requests.getRequest(url)
        Utils.storeTaraServiceUrlToflow(flow, initOIDCServiceSession.getHeader("location"))
        Utils.setParameter(flow.taraService.cookies, "__Host-ory_hydra_login_csrf_624229327", initOIDCServiceSession.getCookie("__Host-ory_hydra_login_csrf_624229327"))
        Response initLogin = Steps.followRedirect(flow, initOIDCServiceSession)
        flow.taraService.setSessionId(initLogin.getCookie("__Host-SESSION"))
        flow.taraService.setLogin_locale(initLogin.getCookie("__Host-LOCALE"))
        if (initLogin.body.prettyPrint().contains("_csrf")) {
            flow.taraService.setCsrf(initLogin.body.htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        }
        return initLogin
    }

    @Step("Initialize authentication sequence in login service")
    static Response createLoginSession(Flow flow, Response response) {
        Response initLogin = Steps.followRedirect(flow, response)
        flow.taraService.setSessionId(initLogin.getCookie("__Host-SESSION"))
        flow.taraService.setLogin_locale(initLogin.getCookie("__Host-LOCALE"))
        if (initLogin.body.prettyPrint().contains("_csrf")) {
            flow.taraService.setCsrf(initLogin.body.htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        }
        return initLogin
    }


    @Step("Polling Mobile-ID authentication response")
    static Response pollMidResponse(Flow flow, long pollingIntevalMillis = 2000L) {
        int counter = 0
        Response response = null
        while (counter < 12) {
            sleep(pollingIntevalMillis)
            response = pollMid(flow)
            if (response.body.path("status") != "PENDING") {
                break
            }
            ++counter
        }
        return response
    }

    @Step("Authenticate with Mobile-ID")
    static Response authenticateWithMid(Flow flow, String idCode, String phoneNo) {
        startMidAuthentication(flow, idCode, phoneNo)
        pollMidResponse(flow)
        Response acceptResponse = acceptAuthTara(flow, flow.taraService.taraloginBaseUrl + flow.taraService.authAcceptUrl)
        Response oidcServiceResponse = Requests.followRedirectWithCookies(flow, acceptResponse.getHeader("location"), flow.taraService.cookies)
        Utils.setParameter(flow.taraService.cookies, "__Host-ory_hydra_consent_csrf_624229327", oidcServiceResponse.getCookie("__Host-ory_hydra_consent_csrf_624229327"))
        return Requests.getRequestWithSessionId(flow, oidcServiceResponse.getHeader("location"))
    }

    @Step("Authenticate with Smart-ID")
    static Response authenticateWithSid(Flow flow, String idCode) {
        startSidAuthentication(flow, idCode)
        pollSidResponse(flow)
        Response acceptResponse = acceptAuthTara(flow, flow.taraService.taraloginBaseUrl + flow.taraService.authAcceptUrl)
        Response oidcServiceResponse = Requests.followRedirectWithCookies(flow, acceptResponse.getHeader("location"), flow.taraService.cookies)
        Utils.setParameter(flow.taraService.cookies, "__Host-ory_hydra_consent_csrf_624229327", oidcServiceResponse.getCookie("__Host-ory_hydra_consent_csrf_624229327"))
        return Requests.getRequestWithSessionId(flow, oidcServiceResponse.getHeader("location"))
    }

    @Step("Authenticate with eIDAS")
    static Response authenticateWithEidas(Flow flow, String country, String username, String password, String loa) {
        Map queryParamsMap = [country: country,
                              _csrf  : flow.taraService.csrf]
        Map cookieMap = ["__Host-SESSION": flow.taraService.sessionId]
        Response initEidasAuthenticationSession = Requests.postRequestWithCookiesAndParams(flow, flow.taraService.taraloginBaseUrl + flow.taraService.eidasInitUrl, cookieMap, queryParamsMap)
        flow.setNextEndpoint(initEidasAuthenticationSession.body.htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.body.htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.body.htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))

        Response serviceProviderResponse = eidasServiceProviderRequest(flow, flow.nextEndpoint, flow.relayState, flow.requestMessage)
        Response specificconnectorResponse = eidasSpecificConnectorRequest(flow, serviceProviderResponse)
        Response colleagueResponse = eidasColleagueRequest(flow, specificconnectorResponse)
        String endpointUrl = colleagueResponse.body.htmlPath().getString("**.find { it.@id == 'redirectForm' }.@action")
        String token = colleagueResponse.body.htmlPath().getString("**.find { it.@id == 'token' }.@value")
        Response eidasProxyResponse = eidasProxyServiceRequest(flow, endpointUrl, token)

        Response initIdpResponse = eidasIdpRequest(flow, eidasProxyResponse)
        Response authorizationRequest = eidasIdpAuthorizationRequest(flow, initIdpResponse, username, password, loa)
        Response authorizationResponse = eidasIdpAuthorizationResponse(flow, authorizationRequest)

        String binaryLightToken = authorizationResponse.body.htmlPath().get("**.find {it.@id == 'binaryLightToken'}.@value")
        Response consentResponse = eidasConfirmConsent(flow, binaryLightToken)
        String endpointUrl2 = consentResponse.body.htmlPath().getString("**.find { it.@id == 'redirectForm' }.@action")
        String token2 = consentResponse.body.htmlPath().getString("**.find { it.@id == 'token' }.@value")
        Response eidasProxyResponse2 = eidasProxyServiceRequest(flow, endpointUrl2, token2)
        Response colleagueResponse2 = eidasColleagueResponse(flow, eidasProxyResponse2)
        Response authorizationResponse2 = getAuthorizationResponseFromEidas(flow, colleagueResponse2)
        Response redirectionResponse = eidasRedirectAuthorizationResponse(flow, authorizationResponse2)
        flow.taraService.setCsrf(redirectionResponse.body.htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        Response acceptResponse = acceptAuthTara(flow, flow.taraService.taraloginBaseUrl + flow.taraService.authAcceptUrl)
        Response oidcServiceResponse = Requests.followRedirectWithCookies(flow, acceptResponse.getHeader("location"), flow.taraService.cookies)
        Utils.setParameter(flow.taraService.cookies, "__Host-ory_hydra_consent_csrf_624229327", oidcServiceResponse.getCookie("__Host-ory_hydra_consent_csrf_624229327"))
        return Requests.getRequestWithSessionId(flow, oidcServiceResponse.getHeader("location"))
    }

    @Step("Polling Smart-ID authentication response")
    static Response pollSidResponse(Flow flow, long pollingIntevalMillis = 2000L) {
        int counter = 0
        Response response = null
        while (counter < 20) {
            response = pollSid(flow)
            if (response.body.path("status") != "PENDING") {
                break
            }
            ++counter
            sleep(pollingIntevalMillis)
        }
        return response
    }

    @Step("Authenticate with MID in TARA")
    static Response authenticateWithMidInTARA(Flow flow, String idCode, String phoneNo, Response response) {
        startAuthenticationInTara(flow, response.getHeader("location"))
        Response midAuthResponse = authenticateWithMid(flow, idCode, phoneNo)
        return Requests.followRedirectWithCookies(flow, midAuthResponse.getHeader("location"), flow.taraService.cookies)
    }

    @Step("Authenticate with SID in TARA")
    static Response authenticateWithSidInTARA(Flow flow, String idCode, Response response) {
        startAuthenticationInTara(flow, response.getHeader("location"))
        Response sidAuthResponse = authenticateWithSid(flow, idCode)
        return Requests.followRedirectWithCookies(flow, sidAuthResponse.getHeader("location"), flow.taraService.cookies)
    }

    @Step("Authenticate with Web eID in TARA")
    static Response authenticateWithIdCardInTARA(Flow flow, Response response) {
        startAuthenticationInTara(flow, response.getHeader("location"))
        Response initWebEid = postRequestWithSessionId(flow, flow.taraService.fullWebEidInitUrl)
        String signAuthValue = Utils.signAuthenticationValue(flow, flow.taraService.baseUrl, initWebEid.path("nonce"))
        JSONObject authToken = Utils.getWebEidAuthTokenParameters(flow, signAuthValue)
        postRequestWithJsonBody(flow, flow.taraService.fullWebEidLoginUrl, authToken)
        Response loginResponse = postRequestWithSessionId(flow, flow.taraService.fullAuthAcceptUrl)
        Response oidcLoginVerifier = Steps.followRedirectWithCookies(flow, loginResponse, flow.taraService.cookies)
        Utils.setParameter(flow.taraService.cookies, "__Host-ory_hydra_consent_csrf_624229327", oidcLoginVerifier.getCookie("__Host-ory_hydra_consent_csrf_624229327"))
        Response consentResponse = Steps.followRedirectWithCookies(flow, oidcLoginVerifier, flow.taraService.cookies)
        Response oidcConsentVerifier = Steps.followRedirectWithCookies(flow, consentResponse, flow.taraService.cookies)
        return oidcConsentVerifier
    }

    @Step("Authenticate with eIDAS in TARA")
    static Response authenticateWithEidasInTARA(Flow flow, String country, String username, String password, String loa, Response response) {
        startAuthenticationInTara(flow, response.getHeader("location"))
        Response eidasAuthResponse = authenticateWithEidas(flow, country, username, password, loa)
        return Requests.followRedirectWithCookies(flow, eidasAuthResponse.getHeader("location"), flow.taraService.cookies)
    }


    @Step("Post request to init Web eID authentication")
    static Response postRequestWithSessionId(Flow flow, String location) {
        return given()
                .relaxedHTTPSValidation()
                .urlEncodingEnabled(false)
                .filter(flow.cookieFilter)
                .cookie("__Host-SESSION", flow.taraService.sessionId)
                .formParam("_csrf", flow.taraService.csrf)
                .log().cookies()
                .redirects().follow(false)
                .post(location)
    }

    @Step("Post request with json body")
    static Response postRequestWithJsonBody(Flow flow, String location, JSONObject body) {
        return given()
                .relaxedHTTPSValidation()
                .urlEncodingEnabled(true)
                .filter(flow.cookieFilter)
                .cookie("__Host-SESSION", flow.taraService.sessionId)
                .contentType("application/json")
                .header("X-CSRF-TOKEN", flow.taraService.csrf)
                .body(body.toString())
                .post(location)
                .then()
                .log().cookies()
                .extract().response()
    }

    @Step("Mobile-ID authentication init request")
    static Response startMidAuthentication(Flow flow, String idCode, String phoneNo) {
        return given()
                .relaxedHTTPSValidation()
                .urlEncodingEnabled(true)
                .filter(flow.cookieFilter)
                .formParams([idCode         : idCode,
                             telephoneNumber: phoneNo,
                             _csrf          : flow.taraService.csrf])
                .cookie("__Host-SESSION", flow.taraService.sessionId)
                .log().cookies()
                .redirects().follow(false)
                .post(flow.taraService.taraloginBaseUrl + flow.taraService.midInitUrl)
    }

    @Step("Mobile-ID response poll request")
    static Response pollMid(Flow flow) {
        return given()
                .relaxedHTTPSValidation()
                .urlEncodingEnabled(true)
                .filter(flow.cookieFilter)
                .cookie("__Host-SESSION", flow.taraService.sessionId)
                .log().cookies()
                .redirects().follow(false)
                .get(flow.taraService.taraloginBaseUrl + flow.taraService.midPollUrl)
    }

    @Step("Smart-ID authentication init request")
    static Response startSidAuthentication(Flow flow, String idCode) {
        return given()
                .relaxedHTTPSValidation()
                .urlEncodingEnabled(true)
                .filter(flow.cookieFilter)
                .formParams([idCode: idCode,
                             _csrf : flow.taraService.csrf])
                .cookie("__Host-SESSION", flow.taraService.sessionId)
                .log().cookies()
                .redirects().follow(false)
                .post(flow.taraService.taraloginBaseUrl + flow.taraService.sidInitUrl)
    }

    @Step("Smart-ID response poll request")
    static Response pollSid(Flow flow) {
        return given()
                .relaxedHTTPSValidation()
                .urlEncodingEnabled(true)
                .filter(flow.cookieFilter)
                .cookie("__Host-SESSION", flow.taraService.sessionId)
                .cookie("__Host-LOCALE", flow.taraService.login_locale)
                .log().cookies()
                .redirects().follow(false)
                .get(flow.taraService.taraloginBaseUrl + flow.taraService.sidPollUrl)
    }

    @Step("Accept authentication in TARA login service")
    static Response acceptAuthTara(Flow flow, String location) {
        return given()
                .relaxedHTTPSValidation()
                .urlEncodingEnabled(true)
                .filter(flow.cookieFilter)
                .cookie("__Host-SESSION", flow.taraService.sessionId)
                .formParam("_csrf", flow.taraService.csrf)
                .log().cookies()
                .redirects().follow(false)
                .post(location)
    }
}
