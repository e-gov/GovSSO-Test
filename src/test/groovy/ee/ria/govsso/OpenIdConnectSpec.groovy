package ee.ria.govsso

import com.google.common.hash.Hashing
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.qameta.allure.Step
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import com.nimbusds.jose.jwk.JWKSet

import java.nio.charset.StandardCharsets

import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.startsWith
import static org.hamcrest.Matchers.endsWith
import static org.hamcrest.MatcherAssert.assertThat

class OpenIdConnectSpec extends GovSsoSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Feature("OIDC_TOKEN")
    def "Metadata and token key ID matches"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        String keyID = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, createSession.body.jsonPath().get("id_token")).header.keyID

        assertThat("Correct HTTP status code", createSession.statusCode, is(200))
        assertThat("Matching key ID", keyID, is(flow.jwkSet.keys[0].getKeyID()))
    }

    @Feature("OIDC_TOKEN")
    def "Request a token twice"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response consentVerifier = followRedirectsToClientApplication(flow, taraAuthentication)
        String authorizationCode = Utils.getParamValueFromResponseHeader(consentVerifier, "code")
        // 1
        Requests.webTokenBasicRequest(flow, authorizationCode)
        // 2
        Response token2 = Requests.webTokenBasicRequest(flow, authorizationCode)
        assertThat("Correct HTTP status code", token2.statusCode, is(400))
        assertThat("Correct Content-Type", token2.contentType, startsWith("application/json"))
        assertThat("Correct error message", token2.body.jsonPath().getString("error"), is("invalid_grant"))
        assertThat("Correct error_description", token2.body.jsonPath().getString("error_description"), endsWith("The authorization code has already been used."))
    }

    @Feature("OIDC_TOKEN")
    def "Request with invalid authorization code"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response consentVerifier = followRedirectsToClientApplication(flow, taraAuthentication)
        String authorizationCode = Utils.getParamValueFromResponseHeader(consentVerifier, "code")

        Response token = Requests.webTokenBasicRequest(flow, authorizationCode + "e")
        assertThat("Correct HTTP status code", token.statusCode, is(400))
        assertThat("Correct Content-Type", token.contentType, startsWith("application/json"))
        assertThat("Correct error message", token.body.jsonPath().getString("error"), is("invalid_grant"))
    }

    @Feature("OIDC_TOKEN")
    def "Request with missing parameter #paramName"() {
        expect:
        Map formParams = [grant_type  : "code",
                          code        : "1234567",
                          redirect_uri: flow.oidcClientA.fullResponseUrl]
        formParams.remove(paramName)
        Response token = Requests.getWebTokenResponseBody(flow, formParams)

        assertThat("Correct HTTP status code", token.statusCode, is(statusCode))
        assertThat("Correct Content-Type is returned", token.contentType, startsWith("application/json"))
        assertThat("Correct error message", token.body.jsonPath().getString("error"), is(error))
        assertThat("Correct error_description prefix", token.body.jsonPath().get("error_description"), startsWith(errorPrefix))
        assertThat("Correct error_description suffix", token.body.jsonPath().get("error_description"), endsWith(errorSuffix))

        where:
        paramName      || statusCode || error             || errorPrefix                                   || errorSuffix
        "code"         || 400        || "invalid_request" || "The request is missing a required parameter" || "whitelisted the redirect_uri you specified."
        "grant_type"   || 400        || "invalid_request" || "The request is missing a required parameter" || "Request parameter 'grant_type' is missing"
        "redirect_uri" || 400        || "invalid_request" || "The request is missing a required parameter" || "whitelisted the redirect_uri you specified."
    }

    @Feature("OIDC_TOKEN")
    def "Request with invalid parameter value #paramName"() {
        expect:
        Map formParams = [grant_type  : "code",
                          code        : "1234567",
                          redirect_uri: flow.oidcClientA.fullResponseUrl]
        formParams << [(paramName): paramValue]
        Response token = Requests.getWebTokenResponseBody(flow, formParams)

        assertThat("Correct HTTP status code", token.statusCode, is(statusCode))
        assertThat("Correct Content-Type", token.contentType, startsWith("application/json"))
        assertThat("Correct error message", token.body.jsonPath().getString("error"), is(error))
        assertThat("Correct error_description prefix", token.body.jsonPath().get("error_description"), startsWith(errorPrefix))
        assertThat("Correct error_description suffix", token.body.jsonPath().get("error_description"), endsWith(errorSuffix))

        where:
        paramName      | paramValue                || statusCode || error             || errorPrefix                                   || errorSuffix
        "redirect_uri" | "https://www.example.com" || 400        || "invalid_request" || "The request is missing a required parameter" || "whitelisted the redirect_uri you specified."
        "grant_type"   | "token"                   || 400        || "invalid_request" || "The request is missing a required parameter" || "whitelisted the redirect_uri you specified."
        "code"         | "45678"                   || 400        || "invalid_request" || "The request is missing a required parameter" || "whitelisted the redirect_uri you specified."
    }

    @Feature("OIDC_TOKEN")
    def "Request with url encoded nonce"() {
        expect:
        Map paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        flow.setNonce("testȺ田\uD83D\uDE0D&additional=1 %20")
        paramsMap << [nonce: "testȺ田\uD83D\uDE0D&additional=1 %20"]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", initLogin)
        Response consentVerifier = followRedirectsToClientApplication(flow, taraAuthentication)

        Response token = Steps.getIdentityTokenResponseWithDefaults(flow, consentVerifier)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, token.body.jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getClaim("nonce"), equalTo(paramsMap.get("nonce")))
    }

    @Step("Follow redirects to client application")
    static Response followRedirectsToClientApplication(Flow flow, Response authenticationFinishedResponse) {
        Response initLogin = Steps.followRedirectWithCookies(flow, authenticationFinishedResponse, flow.sessionService.cookies)
        Response loginVerifier = Steps.followRedirectWithCookies(flow, initLogin, flow.ssoOidcService.cookies)
        flow.setConsentChallenge(Utils.getParamValueFromResponseHeader(loginVerifier, "consent_challenge"))
        Utils.setParameter(flow.ssoOidcService.cookies, "__Host-ory_hydra_consent_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt(), loginVerifier.getCookie("__Host-ory_hydra_consent_csrf_" + Hashing.murmur3_32().hashString(flow.clientId, StandardCharsets.UTF_8).asInt()))
        Utils.setParameter(flow.ssoOidcService.cookies, "__Host-ory_hydra_session", loginVerifier.getCookie("__Host-ory_hydra_session"))
        Response initConsent = Steps.followRedirectWithCookies(flow, loginVerifier, flow.ssoOidcService.cookies)
        return Steps.followRedirectWithCookies(flow, initConsent, flow.ssoOidcService.cookies)
    }
}
