package ee.ria.govsso

import io.qameta.allure.Step
import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.path.json.JsonPath
import io.restassured.response.Response

import static io.restassured.RestAssured.given

class Requests {


    @Step("Follow redirect request")
    static Response followRedirect(Flow flow, String location) {
        return given()
                .urlEncodingEnabled(false)
                .relaxedHTTPSValidation()
                .filter(flow.cookieFilter)
                .log().cookies()
                .redirects().follow(false)
                .get(location)
    }

    @Step("Follow redirect request with origin")
    static Response followRedirectWithOrigin(Flow flow, String location, String origin) {
        return given()
                .urlEncodingEnabled(false)
                .relaxedHTTPSValidation()
                .filter(flow.cookieFilter)
                .header("Origin", origin)
                .log().cookies()
                .redirects().follow(false)
                .get(location)

    }

    @Step("Follow redirect request with cookies and origin")
    static Response followRedirectWithCookiesAndOrigin(Flow flow, String location, Map myCookies, String origin) {
        return given()
                .urlEncodingEnabled(false)
                .relaxedHTTPSValidation()
                .filter(flow.cookieFilter)
                .cookies(myCookies)
                .header("Origin", origin)
                .log().cookies()
                .redirects().follow(false)
                .get(location)
    }

    @Step("Follow redirect request with additional query params")
    static Response followRedirectWithParams(Flow flow, String location, Map queryParams) {
        return given()
                .urlEncodingEnabled(false)
                .relaxedHTTPSValidation()
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
                .relaxedHTTPSValidation()
                .filter(flow.cookieFilter)
                .cookies(myCookies)
                .log().cookies()
                .redirects().follow(false)
                .header("User-Agent", "Test User-Agent")
                .get(location)
    }

    @Step("Simple get request")
    static Response getRequest(String location) {
        return given()
                .relaxedHTTPSValidation()
                .urlEncodingEnabled(false)
                .log().cookies()
                .redirects().follow(false)
                .get(location)
    }

    @Step("Simple delete request")
    static Response deleteRequest(String location) {
        return given()
                .relaxedHTTPSValidation()
                .urlEncodingEnabled(false)
                .log().cookies()
                .redirects().follow(false)
                .delete(location)
    }

    @Step("Simple {0} request")
    static Response requestWithType(String requestType, String location) {
        return given()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .log().cookies()
                .redirects().follow(false)
                .request(requestType, location)
    }

    @Step("Login service get request with session id")
    static Response getRequestWithSessionId(Flow flow, String location) {
        return given()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .filter(flow.cookieFilter)
                .cookie("SESSION", flow.taraService.sessionId)
                .log().cookies()
                .redirects().follow(false)
                .get(location)
    }

    @Step("Get request with cookies and params")
    static Response getRequestWithCookiesAndParams(Flow flow, String url, Map cookies, Map queryParams) {
        return given()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .filter(flow.cookieFilter)
                .cookies(cookies)
                .queryParams(queryParams)
                .log().cookies()
                .redirects().follow(false)
                .get(url)
    }

    @Step("Get request with cookies and params")
    static Response getRequestWithCookiesParamsAndOrigin(Flow flow, String url
                                                         , Map cookies
                                                         , Map queryParams
                                                         , String origin) {
        return given()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .filter(flow.cookieFilter)
                .cookies(cookies)
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
                .relaxedHTTPSValidation()
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
                .relaxedHTTPSValidation()
                .filter(flow.cookieFilter)
                .queryParams(queryParams)
                .headers(headers)
                .log().cookies()
                .redirects().follow(false)
                .get(url)
    }

    @Step("Post request with cookies, params and origin header")
    static Response postRequestWithCookiesParamsAndOrigin(Flow flow, String url, Map cookies, Map formParams, String origin) {
        return given()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .filter(flow.cookieFilter)
                .cookies(cookies)
                .formParams(formParams)
                .header("Origin", origin)
                .log().cookies()
                .post(url)
    }

    @Step("Post request with cookies and params")
    static Response postRequestWithCookiesAndParams(Flow flow, String url, Map cookies, Map formParams) {
        return given()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .filter(flow.cookieFilter)
                .cookies(cookies)
                .formParams(formParams)
                .log().cookies()
                .post(url)
    }

    @Step("Post request with params")
    static Response postRequestWithParams(Flow flow, String url, Map formParams) {
        return given()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .filter(flow.cookieFilter)
                .formParams(formParams)
                .log().cookies()
                .post(url)
    }

    @Step("Post request with cookies")
    static Response postRequestWithCookies(Flow flow, String url, Map cookies) {
        return given()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .filter(flow.cookieFilter)
                .cookies(cookies)
                .log().cookies()
                .redirects().follow(false)
                .post(url)
    }

    @Step("Get health")
    static Response getHealth(Flow flow) {
        return given()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .get(flow.sessionService.fullHealthUrl)
                .then()
                .statusCode(200)
                .extract().response()
    }

    @Step("Get readiness")
    static Response getReadiness(Flow flow) {
        return given()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .get(flow.sessionService.fullReadinessUrl)
                .then()
                .statusCode(200)
                .extract().response()
    }

    @Step("Get liveness")
    static Response getLiveness(Flow flow) {
        return given()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .get(flow.sessionService.fullLivenessUrl)
                .then()
                .statusCode(200)
                .extract().response()
    }

    @Step("Get info")
    static Response getInfo(Flow flow) {
        return given()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .get(flow.sessionService.fullInfoUrl)
                .then()
                .statusCode(200)
                .extract().response()
    }

    @Step("Download openid service configuration")
    static JsonPath getOpenidConfiguration(String url) {
        return given()
                .relaxedHTTPSValidation()
                .get(url)
                .then()
                .statusCode(200)
                .extract().body().jsonPath()
    }

    @Step("Download openid service JWKS")
    static InputStream getOpenidJwks(String url) {
        return given()
                .relaxedHTTPSValidation()
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
                .relaxedHTTPSValidation()
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
                .filter(new AllureRestAssured())
                .params([grant_type   : "authorization_code",
                         redirect_uri : redirectUrl,
                         code         : authorizationCode,
                         client_id    : clientId,
                         client_secret: clientSecret])
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .post(flow.openIdServiceConfiguration.getString("token_endpoint"))
    }

    @Step("Get session update response")
    static Response getSessionUpdateWebToken(Flow flow, String refreshToken, String clientId, String clientSecret, String redirectUrl) {
        return given()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", refreshToken)
                .formParam("redirect_uri", redirectUrl)
                .auth().preemptive().basic(clientId, clientSecret)
                .post(flow.openIdServiceConfiguration.getString("token_endpoint"))
    }

    @Step("Get token response body")
    static Response getWebTokenResponseBody(Flow flow, Map formParams) {
        return given()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .formParams(formParams)
                .auth().preemptive().basic(flow.oidcClientA.clientId, flow.oidcClientA.clientSecret)
                .post(flow.openIdServiceConfiguration.getString("token_endpoint"))
    }
}
