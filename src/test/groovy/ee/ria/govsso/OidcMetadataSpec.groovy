package ee.ria.govsso

import io.qameta.allure.Feature
import io.restassured.path.json.JsonPath
import io.restassured.response.Response

import static org.junit.jupiter.api.Assertions.*

class OidcMetadataSpec extends GovSsoSpecification {
    Flow flow = new Flow(props)

    @Feature("OIDC_DISCOVERY_ENDPOINT")
    def "Verify discovery path"() {
        expect:
        Response response = Requests.getRequest(flow.ssoOidcService.fullConfigurationUrl)
        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals((flow.ssoOidcService.baseUrl.toString() + "/"), response.getBody().jsonPath().get("issuer"), "Correct issuer")
    }

    //TODO: review userinfo endpoint
    @Feature("OIDC_DISCOVERY_CONTENT")
    def "Verify discovery content"() {
        expect:
        JsonPath jsonResponse = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)

        assertEquals((flow.ssoOidcService.baseUrl.toString() + "/"), jsonResponse.get("issuer"), "Correct issuer")
        assertEquals((flow.ssoOidcService.fullAuthenticationRequestUrl).toString(), jsonResponse.getString("authorization_endpoint"), "Correct authorization endpoint")
        assertEquals((flow.ssoOidcService.baseUrl + "/oauth2/token").toString(), jsonResponse.getString("token_endpoint"), "Correct token endpoint")
        assertEquals((flow.ssoOidcService.fullJwksUrl).toString(), jsonResponse.getString("jwks_uri"), "Correct jwks uri")
        assertEquals(["public"], jsonResponse.getList("subject_types_supported"), "Supported subject type")
        assertEquals(["code"], jsonResponse.getList("response_types_supported"), "Supported response type")
        assertEquals(["authorization_code"], jsonResponse.getList("grant_types_supported"), "Supported grant type")
        assertEquals(["query"], jsonResponse.getList("response_modes_supported"), "Supported response mode")
        assertEquals((flow.ssoOidcService.baseUrl.toString() + "/userinfo"), jsonResponse.get("userinfo_endpoint"), "Correct userinfo endpoint")
        assertEquals(["openid"], jsonResponse.getList("scopes_supported"), "Supported scope")
        assertEquals(["client_secret_basic"], jsonResponse.getList("token_endpoint_auth_methods_supported"), "Correct token endpoint auth method")
        assertEquals(["RS256"], jsonResponse.getList("id_token_signing_alg_values_supported"), "Supported alg values")
        assertTrue(jsonResponse.getBoolean("request_uri_parameter_supported") == (false))
        assertTrue(jsonResponse.getBoolean("claims_parameter_supported") == (false))
        assertTrue(jsonResponse.getBoolean("backchannel_logout_supported") == (true))
        assertTrue(jsonResponse.getBoolean("backchannel_logout_session_supported") == (true))
        assertEquals(["normal"], jsonResponse.getList("claim_types_supported"), "Supported claim types")
        assertEquals(("https://e-gov.github.io/GOVSSO/"), jsonResponse.get("service_documentation"), "Correct service documentation URL")
        assertEquals((flow.ssoOidcService.fullLogoutUrl).toString(), jsonResponse.getString("end_session_endpoint"), "Correct session end endpoint")

        List<String> claimsSupported = jsonResponse.getList("claims_supported")
        def claimsList = ["sub", "acr", "amr", "at_hash", "aud", "auth_time", "exp", "iat", "iss", "jti", "nonce", "birthdate", "family_name", "given_name", "sid"]
        claimsList.each {
            assertTrue(claimsSupported.contains(it), "Claims supported. Contains $it")
        }

        List<String> uiLocalesSupported = jsonResponse.getList("ui_locales_supported")
        def uiLocalesList = ["et", "en", "ru"]
        uiLocalesList.each {
            assertTrue(uiLocalesSupported.contains(it), "UI locales supported. Contains $it")
        }

        List<String> acrValuesSupported = jsonResponse.getList("acr_values_supported")
        def acrValuesList = ["low", "substantial", "high"]
        acrValuesList.each {
            assertTrue(acrValuesSupported.contains(it), "Acr values supported. Contains $it")
        }
    }

    @Feature("OIDC_ENDPOINTS")
    def "Verify keystore endpoint"() {
        expect:
        JsonPath jsonResponse = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        Response response = Requests.getRequest(jsonResponse.getString("jwks_uri"))
        assertTrue(response.getBody().jsonPath().getString("keys.n").size() > 300, "Correct n size")
        assertTrue(response.getBody().jsonPath().getString("keys.e").size() > 3, "Correct e size")
    }

}