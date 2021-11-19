package ee.ria.govsso

import io.qameta.allure.Step
import io.restassured.response.Response

class EidasSteps {

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
}
