package ee.ria.govsso

import io.qameta.allure.Step
import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.RestAssured
import io.restassured.path.json.JsonPath
import io.restassured.response.Response

import static io.restassured.RestAssured.given
import static io.restassured.config.EncoderConfig.encoderConfig

class Requests {


    @Step("Follow redirect request")
    static Response followRedirect(Flow flow, String location) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .log().cookies()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response()
    }

    @Step("Follow redirect request with origin")
    static Response followRedirectWithOrigin(Flow flow, String location, String origin) {
        return given()
                .filter(flow.cookieFilter)
                .header("Origin", origin)
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .log().cookies()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response()
    }

    @Step("Follow redirect request with cookies and origin")
    static Response followRedirectWithCookiesAndOrigin(Flow flow, String location, Map myCookies, String origin) {
        return given()
                .filter(flow.cookieFilter)
                .cookies(myCookies)
                .header("Origin", origin)
                .filter(new AllureRestAssured())
                .log().cookies()
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response()
    }

    @Step("Follow redirect request with additional query params")
    static Response followRedirectWithParams(Flow flow, String location, Map<String, String> additionalQueryParams) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .queryParams(additionalQueryParams)
                .relaxedHTTPSValidation()
                .log().cookies()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response()
    }

    @Step("Simple get request")
    static Response getRequest(String location) {
        return given()
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .log().cookies()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response()
    }

    @Step("Login service get request with session id")
    static Response getRequestWithSessionId(Flow flow, String location) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .cookie("SESSION", flow.taraService.sessionId)
                .log().cookies()
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .get(location)
                .then()
                .extract().response()
    }

    @Step("Follow redirect with cookie request")
    static Response followRedirectWithCookie(Flow flow, String location, Map myCookies) {
        return given()
                .filter(flow.cookieFilter)
                .cookies(myCookies)
                .filter(new AllureRestAssured())
                .log().cookies()
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response()
    }

    @Step("Get request with cookies and params")
    static Response getRequestWithCookiesAndParams(Flow flow, String url
                                                   , Map<String, String> cookies
                                                   , Map<String, String> queryParams
                                                   , Map<String, String> additionalQueryParams) {
        return given()
                .filter(flow.cookieFilter)
                .cookies(cookies)
                .queryParams(queryParams)
                .queryParams(additionalQueryParams)
                .filter(new AllureRestAssured())
                .log().cookies()
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(true)
                .get(url)
                .then()
                .extract().response()
    }

    @Step("Get request with cookies and params")
    static Response getRequestWithCookiesParamsAndOrigin(Flow flow, String url
                                                   , Map<String, String> cookies
                                                   , Map<String, String> queryParams
                                                   , String origin) {
        return given()
                .filter(flow.cookieFilter)
                .cookies(cookies)
                .queryParams(queryParams)
                .header("Origin", origin)
                .filter(new AllureRestAssured())
                .log().cookies()
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(true)
                .get(url)
                .then()
                .extract().response()
    }


    @Step("Get request with params")
    static Response getRequestWithParams(Flow flow, String url
                                         , Map<String, String> queryParams
                                         , Map<String, String> additionalQueryParams) {
        return given()
                .filter(flow.cookieFilter)
                .queryParams(queryParams)
                .queryParams(additionalQueryParams)
                .filter(new AllureRestAssured())
                .log().cookies()
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(true)
                .get(url)
                .then()
                .extract().response()
    }

    @Step("Get request with headers and params")
    static Response getRequestWithHeadersAndParams(Flow flow, String url
                                                   , Map<String, String> headers
                                                   , Map<String, String> queryParams
                                                   , Map<String, String> additionalQueryParams) {
        return given()
                .filter(flow.cookieFilter)
                .queryParams(queryParams)
                .headers(headers)
                .queryParams(additionalQueryParams)
                .filter(new AllureRestAssured())
                .log().cookies()
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(true)
                .get(url)
                .then()
                .extract().response()
    }

    @Step("Post request with cookies, params and origin header")
    static Response postRequestWithCookiesParamsAndOrigin(Flow flow, String url, Map<String, String> cookies, Map<String, String> formParams, String origin) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .cookies(cookies)
                .formParams(formParams)
                .header("Origin", origin)
                .log().cookies()
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                .when()
                .post(url)
                .then()
                .extract().response()
    }

    @Step("Post request with cookies and params")
    static Response postRequestWithCookiesAndParams(Flow flow, String url, Map<String, String> cookies, Map<String, String> formParams) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .cookies(cookies)
                .formParams(formParams)
                .log().cookies()
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                .when()
                .post(url)
                .then()
                .extract().response()
    }

    @Step("Post request with params")
    static Response postRequestWithParams(Flow flow, String url, Map<String, String> formParams) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .formParams(formParams)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                .log().cookies()
                .when()
                .post(url)
                .then()
                .extract().response()
    }

    @Step("Post request with cookies")
    static Response postRequestWithCookies(Flow flow, String url, Map<String, String> cookies) {
        return given()
                .filter(flow.cookieFilter)
                .cookies(cookies)
                .filter(new AllureRestAssured())
                .log().cookies()
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(true)
                .post(url)
                .then()
                .extract().response()
    }

    @Step("Get health")
    static Response getHealth(Flow flow) {
        return given()
                .filter(new AllureRestAssured())
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                .when()
                .get(flow.sessionService.fullHealthUrl)
                .then()
                .statusCode(200)
                .extract().response()
    }

    @Step("Get readiness")
    static Response getReadiness(Flow flow) {
        return given()
                .filter(new AllureRestAssured())
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                .when()
                .get(flow.sessionService.fullReadinessUrl)
                .then()
                .statusCode(200)
                .extract().response()
    }

    @Step("Get info")
    static Response getInfo(Flow flow) {
        return given()
                .filter(new AllureRestAssured())
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                .when()
                .get(flow.sessionService.fullInfoUrl)
                .then()
                .statusCode(200)
                .extract().response()
    }

    @Step("Get request with ID-Card authentication")
    static Response idCardAuthentication(Flow flow, Map<String, String> headers) {
        return given()
                .filter(flow.cookieFilter)
                .headers(headers)
                .auth().preemptive().basic(flow.taraService.idCardEndpointUsername, flow.taraService.idCardEndpointPassword)
                .cookie("SESSION", flow.taraService.sessionId)
                .relaxedHTTPSValidation()
                .log().cookies()
                .filter(new AllureRestAssured())
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(flow.taraService.fullIdCardInitUrl)
                .then()
                .extract().response()
    }

    @Step("Download openid service configuration")
    static JsonPath getOpenidConfiguration(String url) {
        return given()
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .when()
                .get(url)
                .then()
                .statusCode(200)
                .extract().body().jsonPath()
    }

    @Step("Download openid service JWKS")
    static InputStream getOpenidJwks(String url) {
        return given()
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .when()
                .get(url)
                .then()
                .statusCode(200)
                .extract().body().asInputStream()
    }

    @Step("Get token with defaults")
    static Response getWebTokenWithDefaults(Flow flow, String authorizationCode) {
        return given()
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                .filter(new AllureRestAssured())
                .formParam("grant_type", "authorization_code")
                .formParam("code", authorizationCode)
                .formParam("redirect_uri", flow.oidcClientA.fullResponseUrl)
                .auth().preemptive().basic(flow.oidcClientA.clientId, flow.oidcClientA.clientSecret)
                .when()
                .urlEncodingEnabled(true)
                .post(flow.openIdServiceConfiguration.getString("token_endpoint"))
                .then()
                .extract().response()
    }

    @Step("Get token")
    static Response getWebToken(Flow flow, String authorizationCode, String clientId, String clientSecret, String redirectUrl) {
        return given()
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                .filter(new AllureRestAssured())
                .formParam("grant_type", "authorization_code")
                .formParam("code", authorizationCode)
                .formParam("redirect_uri", redirectUrl)
                .auth().preemptive().basic(clientId, clientSecret)
                .when()
                .urlEncodingEnabled(true)
                .post(flow.openIdServiceConfiguration.getString("token_endpoint"))
                .then()
                .extract().response()
    }

    @Step("Get token response body")
    static Response getWebTokenResponseBody(Flow flow, Map<String, String> formParams) {
        return given()
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                .filter(new AllureRestAssured())
                .formParams(formParams)
                .auth().preemptive().basic(flow.oidcClientA.clientId, flow.oidcClientA.clientSecret)
                .when()
                .urlEncodingEnabled(true)
                .post(flow.openIdServiceConfiguration.getString("token_endpoint"))
                .then()
                .extract().response()
    }
}
