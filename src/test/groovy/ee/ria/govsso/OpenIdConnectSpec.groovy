package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import ee.ria.govsso.model.HydraError
import ee.ria.govsso.util.HydraErrorValidator
import io.qameta.allure.Feature
import io.qameta.allure.Step
import io.restassured.response.Response

import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.hasItem
import static org.hamcrest.Matchers.endsWith
import static org.hamcrest.MatcherAssert.assertThat

class OpenIdConnectSpec extends GovSsoOidcSpecification {

    @Feature("OIDC_TOKEN")
    def "Metadata and token key ID matches"() {
        expect:
        Response createSession = Steps.authenticateWithIdCardInGovSso(flow)
        String keyID = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, createSession.body.path("id_token")).header.keyID

        assertThat("Correct HTTP status code", createSession.statusCode, is(200))
        assertThat("Matching key ID", flow.jwkSet.keys*.keyID, hasItem(keyID))
    }

    @Feature("OIDC_TOKEN")
    def "Tokens from session update are verifiable with freshly downloaded JWKS"() {
        given: "Create session"
        Steps.authenticateWithIdCardInGovSso(flow, ClientStore.clientB, "access_token")

        when: "Update session and download JWKS after the tokens were issued"
        Response updateSession = Steps.updateSession(flow, ClientStore.clientB)
        JWKSet freshJwks = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))

        then:
        assertThat("ID token signature valid", OpenIdUtils.isTokenSignatureValid(freshJwks, SignedJWT.parse(updateSession.body.path("id_token") as String)), is(true))
        assertThat("Access token signature valid", OpenIdUtils.isTokenSignatureValid(freshJwks, SignedJWT.parse(updateSession.body.path("access_token") as String)), is(true))
    }

    @Feature("OIDC_TOKEN")
    def "Request a token twice"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response consentVerifier = followRedirectsToClientApplication(flow, taraAuthentication)
        String authorizationCode = Utils.getParamValueFromResponseHeader(consentVerifier, "code")
        // 1
        Requests.webTokenBasicRequest(flow, authorizationCode)
        // 2
        Response token2 = Requests.webTokenBasicRequest(flow, authorizationCode)
        HydraErrorValidator.validate(token2, HydraError.INVALID_GRANT, endsWith("The authorization code has already been used."))
    }

    @Feature("OIDC_TOKEN")
    def "Request with invalid authorization code"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithIdCardInTARA(flow, initLogin)
        Response consentVerifier = followRedirectsToClientApplication(flow, taraAuthentication)
        String authorizationCode = Utils.getParamValueFromResponseHeader(consentVerifier, "code")

        Response token = Requests.webTokenBasicRequest(flow, authorizationCode + "e")
        HydraErrorValidator.validate(token, HydraError.INVALID_GRANT)
    }

    @Feature("OIDC_TOKEN")
    def "Request with missing parameter #paramName"() {
        expect:
        Map formParams = [grant_type  : "code",
                          code        : "1234567",
                          redirect_uri: ClientStore.clientA.redirectUri]
        formParams.remove(paramName)
        Response token = Requests.tokenRequest(flow, formParams)

        HydraErrorValidator.validate(token, HydraError.INVALID_REQUEST, endsWith(hintSuffix))

        where:
        paramName      || hintSuffix
        "code"         || "whitelisted the redirect_uri you specified."
        "grant_type"   || "Request parameter 'grant_type' is missing"
        "redirect_uri" || "whitelisted the redirect_uri you specified."
    }

    @Feature("OIDC_TOKEN")
    def "Request with invalid parameter value #paramName"() {
        expect:
        Map formParams = [grant_type  : "code",
                          code        : "1234567",
                          redirect_uri: ClientStore.clientA.redirectUri]
        formParams << [(paramName): paramValue]
        Response token = Requests.tokenRequest(flow, formParams)

        HydraErrorValidator.validate(token, HydraError.INVALID_REQUEST, endsWith(hintSuffix))

        where:
        paramName      | paramValue                || hintSuffix
        "redirect_uri" | "https://www.example.com" || "whitelisted the redirect_uri you specified."
        "grant_type"   | "token"                   || "whitelisted the redirect_uri you specified."
        "code"         | "45678"                   || "whitelisted the redirect_uri you specified."
    }

    @Feature("OIDC_TOKEN")
    def "Request with url encoded nonce"() {
        expect:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        flow.setNonce("testȺ田\uD83D\uDE0D&additional=1 %20")
        paramsMap << [nonce: "testȺ田\uD83D\uDE0D&additional=1 %20"]
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraAuthentication = TaraSteps.authenticateWithMidInTARA(flow, "60001017716", "59100366", initLogin)
        Response consentVerifier = followRedirectsToClientApplication(flow, taraAuthentication)

        Response token = Steps.getTokenResponseWithDefaults(flow, consentVerifier)

        JWTClaimsSet claims = OpenIdUtils.verifyTokenAndReturnSignedJwtObject(flow, token.body.path("id_token")).JWTClaimsSet
        assertThat(claims.getClaim("nonce"), equalTo(paramsMap.get("nonce")))
    }

    @Step("Follow redirects to client application")
    static Response followRedirectsToClientApplication(Flow flow, Response authenticationFinishedResponse) {
        Response initLogin = Steps.followRedirect(flow, authenticationFinishedResponse)
        Response loginVerifier = Steps.followRedirect(flow, initLogin)
        flow.setConsentChallenge(Utils.getParamValueFromResponseHeader(loginVerifier, "consent_challenge"))
        Response initConsent = Steps.followRedirect(flow, loginVerifier)
        return Steps.followRedirect(flow, initConsent)
    }
}
