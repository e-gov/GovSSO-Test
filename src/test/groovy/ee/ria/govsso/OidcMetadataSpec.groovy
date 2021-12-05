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

    //TODO: review after GSSO-161
    @Feature("OIDC_DISCOVERY_CONTENT")
    def "Verify discovery content"() {
        expect:
        JsonPath jsonResponse = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)

        assertEquals((flow.ssoOidcService.baseUrl.toString() + "/"), jsonResponse.get("issuer"), "Correct issuer")
        assertEquals((flow.ssoOidcService.fullAuthenticationRequestUrl).toString(), jsonResponse.getString("authorization_endpoint"), "Correct authorization endpoint")
        assertEquals((flow.ssoOidcService.baseUrl + "/oauth2/token").toString(), jsonResponse.getString("token_endpoint"), "Correct token endpoint")
        assertEquals((flow.ssoOidcService.fullJwksUrl).toString(), jsonResponse.getString("jwks_uri"), "Correct jwks uri")

        assertEquals(["public"], jsonResponse.getList("subject_types_supported"), "Supported subject types")

        List<String> responsesSupported = jsonResponse.getList("response_types_supported")
        def responseList = ["code", "code id_token", "id_token", "token id_token", "token", "token id_token code"]
        responseList.each {
            assertTrue(responsesSupported.contains(it), "Response Types Supported. Contains $it")
        }

        List<String> claimsSupported = jsonResponse.getList("claims_supported")
        def claimsList = ["sub", "acr", "amr", "at_has", "aud", "auth_time", "exp", "iat", "iss", "jti", "nonce", "profile_attributes.date_of_birth", "profile_attributes.family_name", "profile_attributes.given_name", "sid"]
        claimsList.each {
            assertTrue(claimsSupported.contains(it), "Claims supported. Contains $it")
        }

        List<String> grantTypesSupported = jsonResponse.getList("grant_types_supported")
        def grantTypesList = ["authorization_code", "implicit", "client_credentials", "refresh_token"]
        grantTypesList.each {
            assertTrue(grantTypesSupported.contains(it), "Claims supported. Contains $it")
        }

        List<String> responseModesSupported = jsonResponse.getList("response_modes_supported")
        def responseModeList = ["query", "fragment"]
        responseModeList.each {
            assertTrue(responseModesSupported.contains(it), "Claims supported. Contains $it")
        }

        assertEquals((flow.ssoOidcService.baseUrl.toString() + "/userinfo"), jsonResponse.get("userinfo_endpoint"), "Correct userinfo endpoint")

        List<String> scopesSupported = jsonResponse.getList("scopes_supported")
        def scopeList = ["openid", "offline_access", "offline"]
        scopeList.each {
            assertTrue(scopesSupported.contains(it), "Scope supported. Contains $it")
        }

        List<String> tokenEndpointAuthMethodsSupported = jsonResponse.getList("token_endpoint_auth_methods_supported")
        def tokenEndpointAuthMethodsList = ["client_secret_post", "client_secret_basic", "private_key_jwt", "none"]
        tokenEndpointAuthMethodsList.each {
            assertTrue(tokenEndpointAuthMethodsSupported.contains(it), "Scope supported. Contains $it")
        }

        List<String> userinfoSigningAlgValuesSupported = jsonResponse.getList("userinfo_signing_alg_values_supported")
        def userinfoSigningAlgValuesList = ["none", "RS256"]
        userinfoSigningAlgValuesList.each {
            assertTrue(userinfoSigningAlgValuesSupported.contains(it), "Scope supported. Contains $it")
        }

        assertEquals(["RS256"], jsonResponse.getList("id_token_signing_alg_values_supported"), "Supported alg values")

        assertTrue(jsonResponse.getBoolean("request_parameter_supported") == true)
        assertTrue(jsonResponse.getBoolean("request_uri_parameter_supported") == (true))
        assertTrue(jsonResponse.getBoolean("require_request_uri_registration") == (true))
        assertTrue(jsonResponse.getBoolean("claims_parameter_supported") == (false))
        assertTrue(jsonResponse.getBoolean("backchannel_logout_supported") == (true))
        assertTrue(jsonResponse.getBoolean("backchannel_logout_session_supported") == (true))
        assertTrue(jsonResponse.getBoolean("frontchannel_logout_supported") == (true))
        assertTrue(jsonResponse.getBoolean("frontchannel_logout_session_supported") == (true))
        assertEquals((flow.ssoOidcService.fullRevocationUrl).toString(), jsonResponse.getString("revocation_endpoint"), "Correct revocation endpoint")
        assertEquals((flow.ssoOidcService.fullLogoutUrl).toString(), jsonResponse.getString("end_session_endpoint"), "Correct session end endpoint")

        List<String> codeChallengeMethodsSupported = jsonResponse.getList("code_challenge_methods_supported")
        def codeChallengeMethodList = ["plain", "S256"]
        codeChallengeMethodList.each {
            assertTrue(codeChallengeMethodsSupported.contains(it), "Scope supported. Contains $it")
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