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
//TODO: nbf not used in govsso?
//        assertThat("Expected current: " + date + " to be after nbf: " + signedJWT.getJWTClaimsSet().getNotBeforeTime(), date.after(signedJWT.getJWTClaimsSet().getNotBeforeTime()), is(true))
        if (!flow.getNonce().isEmpty()) {
            assertThat(signedJWT.getJWTClaimsSet().getStringClaim("nonce"), equalTo(flow.getNonce()))
        }
//TODO: state is not propagated to JWT in govsso?
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

    @Step("Follow redirects to client application")
    static Response followRedirectsToClientApplication (Flow flow, Response authenticationFinishedResponse) {
        Response sessionServiceResponse = Steps.followRedirectWithCookies(flow, authenticationFinishedResponse, flow.ssoOidcService.cookies)
        Response oidcServiceResponse = Steps.followRedirectWithCookies(flow, sessionServiceResponse, flow.ssoOidcService.cookies)
        Utils.setParameter(flow.ssoOidcService.cookies, "oauth2_consent_csrf_insecure", oidcServiceResponse.getCookie("oauth2_consent_csrf_insecure"))
        Response sessionServiceConsentResponse = Steps.followRedirectWithCookies(flow, oidcServiceResponse, flow.ssoOidcService.cookies)
        return Steps.followRedirectWithCookies(flow, sessionServiceConsentResponse, flow.ssoOidcService.cookies)
    }

    private static void addJsonAttachment(String name, String json) throws IOException {
        ObjectMapper mapper = new ObjectMapper()
        Object jsonObject = mapper.readValue(json, Object.class)
        String prettyJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject)
        Allure.addAttachment(name, "application/json", prettyJson, "json")
    }
}
