package ee.ria.govsso

import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import com.nimbusds.jose.jwk.JWKSet

import static org.hamcrest.Matchers.*
import static org.hamcrest.MatcherAssert.assertThat

class OpenIdConnectSpec extends GovSsoSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Feature("OPENID_CONNECT")
    def "Metadata and token key ID matches"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovsso(flow)
        String keyID = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, createSession.getBody().jsonPath().get("id_token")).getHeader().getKeyID()

        assertThat("Correct HTTP status code", createSession.statusCode(), is(200))
        assertThat("Matching key ID", keyID, is(flow.jwkSet.getKeys().get(0).getKeyID()))
    }

    @Feature("OPENID_CONNECT")
    def "Request a token twice"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response consentVerifier = Steps.followRedirectsToClientApplication(flow, taraAuthentication)
        String authorizationCode = Utils.getParamValueFromResponseHeader(consentVerifier, "code")
        // 1
        Requests.getWebTokenWithDefaults(flow, authorizationCode)
        // 2
        Response token2 = Requests.getWebTokenWithDefaults(flow, authorizationCode)
        assertThat("Correct HTTP status code", token2.statusCode(), is(400))
        assertThat("Correct Content-Type", token2.getContentType(), startsWith("application/json"))
        assertThat("Correct error message", token2.body().jsonPath().getString("error"), is("invalid_grant"))
        assertThat("Correct error_description", token2.body().jsonPath().getString("error_description"), endsWith("The authorization code has already been used."))
    }

    @Feature("OPENID_CONNECT")
    def "Request with invalid authorization code"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response consentVerifier = Steps.followRedirectsToClientApplication(flow, taraAuthentication)
        String authorizationCode = Utils.getParamValueFromResponseHeader(consentVerifier, "code")

        Response token = Requests.getWebTokenWithDefaults(flow, authorizationCode + "e")
        assertThat("Correct HTTP status code", token.statusCode(), is(400))
        assertThat("Correct Content-Type", token.getContentType(), startsWith("application/json"))
        assertThat("Correct error message", token.body().jsonPath().getString("error"), is("invalid_grant"))
    }

    @Feature("OPENID_CONNECT")
    def "Request with missing parameter #paramName"() {
        expect:
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "grant_type", "code")
        Utils.setParameter(formParamsMap, "code", "1234567")
        Utils.setParameter(formParamsMap, "redirect_uri", flow.oidcClientA.fullResponseUrl)
        formParamsMap.remove(paramName)
        Response token = Requests.getWebTokenResponseBody(flow, formParamsMap)

        assertThat("Correct HTTP status code", token.statusCode(), is(statusCode))
        assertThat("Correct Content-Type is returned", token.getContentType(), startsWith("application/json"))
        assertThat("Correct error message", token.body().jsonPath().getString("error"), is(error))
        assertThat("Correct error_description prefix", token.body().jsonPath().get("error_description"), startsWith(errorPrefix))
        assertThat("Correct error_description suffix", token.body().jsonPath().get("error_description"), endsWith(errorSuffix))

        where:
        paramName      || statusCode || error             || errorPrefix                                   || errorSuffix
        "code"         || 400        || "invalid_request" || "The request is missing a required parameter" || "whitelisted the redirect_uri you specified."
        "grant_type"   || 400        || "invalid_request" || "The request is missing a required parameter" || "Request parameter 'grant_type' is missing"
        "redirect_uri" || 400        || "invalid_request" || "The request is missing a required parameter" || "whitelisted the redirect_uri you specified."
    }

    @Feature("OPENID_CONNECT")
    def "Request with invalid parameter value #paramName"() {
        expect:
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "grant_type", "code")
        Utils.setParameter(formParamsMap, "code", "1234567")
        Utils.setParameter(formParamsMap, "redirect_uri", flow.oidcClientA.fullResponseUrl)
        Utils.setParameter(formParamsMap, paramName, paramValue)
        Response token = Requests.getWebTokenResponseBody(flow, formParamsMap)

        assertThat("Correct HTTP status code", token.statusCode(), is(statusCode))
        assertThat("Correct Content-Type", token.getContentType(), startsWith("application/json"))
        assertThat("Correct error message", token.body().jsonPath().getString("error"), is(error))
        assertThat("Correct error_description prefix", token.body().jsonPath().get("error_description"), startsWith(errorPrefix))
        assertThat("Correct error_description suffix", token.body().jsonPath().get("error_description"), endsWith(errorSuffix))

        where:
        paramName      | paramValue                || statusCode || error             || errorPrefix                                   || errorSuffix
        "redirect_uri" | "https://www.example.com" || 400        || "invalid_request" || "The request is missing a required parameter" || "whitelisted the redirect_uri you specified."
        "grant_type"   | "token"                   || 400        || "invalid_request" || "The request is missing a required parameter" || "whitelisted the redirect_uri you specified."
        "code"         | "45678"                   || 400        || "invalid_request" || "The request is missing a required parameter" || "whitelisted the redirect_uri you specified."
    }

    @Feature("OPENID_CONNECT")
    def "Request with url encoded nonce"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersWithDefaults(flow)
        flow.setNonce("testȺ田\uD83D\uDE0D&additional=1 %20")
        paramsMap.put("nonce", "testȺ田\uD83D\uDE0D&additional=1 %20")
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "69100366", initLogin)
        Response consentVerifier = Steps.followRedirectsToClientApplication(flow, taraAuthentication)

        Response token = Steps.getIdentityTokenResponseWithDefaults(flow, consentVerifier)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObjectWithDefaults(flow, token.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getClaim("nonce"), equalTo(paramsMap.get("nonce")))
    }
}
