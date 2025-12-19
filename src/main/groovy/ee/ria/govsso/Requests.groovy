package ee.ria.govsso

import io.qameta.allure.Step
import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.path.json.JsonPath
import io.restassured.response.Response

import static io.restassured.RestAssured.given

class Requests {

    @Step("GET {endpoint}")
    static Response get(String baseUri, String endpoint) {
        return given()
                .urlEncodingEnabled(true)
                .baseUri(baseUri)
                .get(endpoint)
    }

    @Step("Follow redirect request")
    static Response followRedirect(Flow flow, String location) {
        return given()
                .urlEncodingEnabled(false)
                .filter(flow.cookieFilter)
                .log().cookies()
                .redirects().follow(false)
                .header("User-Agent", "Test User-Agent")
                .get(location)
    }

    @Step("Follow redirect request with origin")
    static Response followRedirectWithOrigin(Flow flow, String location, String origin) {
        return given()
                .urlEncodingEnabled(false)
                .filter(flow.cookieFilter)
                .header("Origin", origin)
                .log().cookies()
                .redirects().follow(false)
                .get(location)

    }

    @Step("Follow redirect request with additional query params")
    static Response followRedirectWithParams(Flow flow, String location, Map queryParams) {
        return given()
                .urlEncodingEnabled(false)
                .filter(flow.cookieFilter)
                .queryParams(queryParams)
                .log().cookies()
                .redirects().follow(false)
                .get(location)
    }

    @Step("Follow redirect with cookies")
    static Response followRedirectWithCookies(Flow flow, String location, Map myCookies) {
        return given()
                .urlEncodingEnabled(false)
                .filter(flow.cookieFilter)
                .cookies(myCookies)
                .log().cookies()
                .redirects().follow(false)
                .get(location)
    }

    @Step("Simple get request")
    static Response getRequest(String location) {
        return given()
                .urlEncodingEnabled(false)
                .log().cookies()
                .redirects().follow(false)
                .get(location)
    }

    @Step("Simple delete request")
    static Response deleteRequest(String location) {
        return given()
                .urlEncodingEnabled(false)
                .log().cookies()
                .redirects().follow(false)
                .delete(location)
    }

    @Step("Simple {0} request")
    static Response requestWithType(String requestType, String location) {
        return given()
                .urlEncodingEnabled(true)
                .log().cookies()
                .redirects().follow(false)
                .request(requestType, location)
    }

    @Step("Login service get request with session id")
    static Response getRequestWithSessionId(Flow flow, String location) {
        return given()
                .urlEncodingEnabled(true)
                .filter(flow.cookieFilter)
                .cookie("__Host-SESSION", flow.taraService.sessionId)
                .log().cookies()
                .redirects().follow(false)
                .get(location)
    }

    @Step("Get request with cookies and params")
    static Response getRequestWithCookiesAndParams(Flow flow, String url, Map cookies, Map queryParams) {
        return given()
                .urlEncodingEnabled(true)
                .filter(flow.cookieFilter)
                .cookies(cookies)
                .queryParams(queryParams)
                .log().cookies()
                .redirects().follow(false)
                .get(url)
    }

    @Step("Get request with cookies and params")
    static Response getRequestWithParamsAndOrigin(Flow flow,
                                                  String url,
                                                  Map queryParams,
                                                  String origin) {
        return given()
                .urlEncodingEnabled(true)
                .filter(flow.cookieFilter)
                .queryParams(queryParams)
                .header("Origin", origin)
                .log().cookies()
                .redirects().follow(false)
                .get(url)
    }


    @Step("Get request with params")
    static Response getRequestWithParams(Flow flow, String url, Map queryParams) {
        return given()
                .urlEncodingEnabled(true)
                .filter(flow.cookieFilter)
                .queryParams(queryParams)
                .log().cookies()
                .redirects().follow(false)
                .get(url)
    }

    @Step("Get request with headers and params")
    static Response getRequestWithHeadersAndParams(Flow flow, String url, Map headers, Map queryParams) {
        return given()
                .urlEncodingEnabled(true)
                .filter(flow.cookieFilter)
                .queryParams(queryParams)
                .headers(headers)
                .log().cookies()
                .redirects().follow(false)
                .get(url)
    }

    @Step("Post request with cookies, params and origin header")
    static Response postRequestWithParamsAndOrigin(Flow flow, String url, Map formParams, String origin) {
        // Rest-Assured filters out form params with null value, but Allure is not able to handle them.
        formParams.removeAll { key, value -> value == null }
        return given()
                .urlEncodingEnabled(true)
                .filter(flow.cookieFilter)
                .formParams(formParams)
                .header("Origin", origin)
                .log().cookies()
                .post(url)
    }

    @Step("Post request with cookies and params")
    static Response postRequestWithCookiesAndParams(Flow flow, String url, Map cookies, Map formParams) {
        // Rest-Assured filters out form params with null value, but Allure is not able to handle them.
        formParams.removeAll { key, value -> value == null }
        return given()
                .urlEncodingEnabled(true)
                .filter(flow.cookieFilter)
                .cookies(cookies)
                .formParams(formParams)
                .log().cookies()
                .post(url)
    }

    @Step("Post request with params")
    static Response postRequestWithParams(Flow flow, String url, Map formParams) {
        // Rest-Assured filters out form params with null value, but Allure is not able to handle them.
        formParams.removeAll { key, value -> value == null }
        return given()
                .urlEncodingEnabled(true)
                .filter(flow.cookieFilter)
                .formParams(formParams)
                .log().cookies()
                .post(url)
    }

    @Step("Post request with cookies")
    static Response postRequest(Flow flow, String url) {
        return given()
                .urlEncodingEnabled(true)
                .filter(flow.cookieFilter)
                .log().cookies()
                .redirects().follow(false)
                .post(url)
    }

    @Step("Download openid service configuration")
    static JsonPath getOpenidConfiguration(String url) {
        return given()
                .get(url)
                .then()
                .statusCode(200)
                .extract().body().jsonPath()
    }

    @Step("Download openid service JWKS")
    static InputStream getOpenidJwks(String url) {
        return given()
                .get(url)
                .then()
                .statusCode(200)
                .extract().body().asInputStream()
    }

    @Step("Get token with defaults")
    static Response webTokenBasicRequest(Flow flow,
                                         String authorizationCode,
                                         String clientId = flow.oidcClientA.clientId,
                                         String clientSecret = flow.oidcClientA.clientSecret,
                                         String redirectUrl = flow.oidcClientA.fullResponseUrl) {
        return given()
                .urlEncodingEnabled(true)
                .params([grant_type  : "authorization_code",
                         code        : authorizationCode,
                         redirect_uri: redirectUrl])
                .auth().preemptive().basic(clientId, clientSecret)
                .post(flow.openIdServiceConfiguration.getString("token_endpoint"))
    }

    @Step("Get token client_secret_post")
    static Response webTokenPostRequest(Flow flow,
                                        String authorizationCode,
                                        String clientId = "client-f",
                                        String clientSecret = "secretf",
                                        String redirectUrl = "https://clientf.localhost:11443/login/oauth2/code/govsso") {
        return given()
                .params([grant_type   : "authorization_code",
                         redirect_uri : redirectUrl,
                         code         : authorizationCode,
                         client_id    : clientId,
                         client_secret: clientSecret])
                .urlEncodingEnabled(true)
                .post(flow.openIdServiceConfiguration.getString("token_endpoint"))
    }

    @Step("Get session update response")
    static Response getSessionUpdateWebToken(Flow flow, String refreshToken, String clientId, String clientSecret) {
        return given()
                .urlEncodingEnabled(true)
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", refreshToken)
                .auth().preemptive().basic(clientId, clientSecret)
                .post(flow.openIdServiceConfiguration.getString("token_endpoint"))
    }

    @Step("Get session update response with client_secret_post")
    static Response getSessionUpdateWebTokenWithClientSecretPost(Flow flow, String refreshToken) {
        return given()
                .urlEncodingEnabled(true)
                .formParams([grant_type   : "refresh_token",
                             refresh_token: refreshToken,
                             client_id    : "client-f",
                             client_secret: "secretf"])
                .post(flow.openIdServiceConfiguration.getString("token_endpoint"))
    }

    @Step("Get session update response with scope")
    static Response getSessionUpdateWebToken(Flow flow, String scope, String refreshToken, String clientId, String clientSecret) {
        return given()
                .urlEncodingEnabled(true)
                .formParam("scope", scope)
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", refreshToken)
                .auth().preemptive().basic(clientId, clientSecret)
                .post(flow.openIdServiceConfiguration.getString("token_endpoint"))
    }

    @Step("Get token response body")
    static Response getWebTokenResponseBody(Flow flow, Map formParams) {
        return given()
                .urlEncodingEnabled(true)
                .formParams(formParams)
                .auth().preemptive().basic(flow.oidcClientA.clientId, flow.oidcClientA.clientSecret)
                .post(flow.openIdServiceConfiguration.getString("token_endpoint"))
    }
}
