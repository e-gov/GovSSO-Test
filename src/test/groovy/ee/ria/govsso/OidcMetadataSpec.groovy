package ee.ria.govsso

import io.qameta.allure.Feature
import io.restassured.path.json.JsonPath
import io.restassured.response.Response

import static org.junit.jupiter.api.Assertions.*

class OidcMetadataSpec extends GovSsoSpecification {
    Flow flow = new Flow(props)

    @Feature("")
    def "Verify discovery path"() {
        expect:
        Response response = Requests.getRequest(flow.ssoOidcService.fullConfigurationUrl)
        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals((flow.ssoOidcService.baseUrl.toString() + "/"), response.getBody().jsonPath().get("issuer"), "Correct issuer")
    }

   //TODO: review content
    @Feature("")
    def "Verify discovery content"() {
        expect:
        JsonPath jsonResponse = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        assertEquals((flow.ssoOidcService.baseUrl.toString() + "/"), jsonResponse.get("issuer"), "Correct issuer")
        List<String> scopesSupported = jsonResponse.getList("scopes_supported")
        def scopeList = ["openid"] //, "eidas", "eidasonly", "idcard", "mid", "smartid", "email", "phone"]
        scopeList.each {
            assertTrue(scopesSupported.contains(it), "Scope supported. Contains $it")
        }

        assertEquals("code", jsonResponse.getList("response_types_supported")[0], "Supported response types")
        assertEquals("public", jsonResponse.getList("subject_types_supported")[0], "Supported subject types")
        assertEquals(["sub"], jsonResponse.getList("claims_supported"), "Supported claims")

        assertTrue(jsonResponse.getBoolean("request_parameter_supported").equals(true))
        assertTrue(jsonResponse.getBoolean("request_uri_parameter_supported").equals(true))
        assertTrue(jsonResponse.getBoolean("require_request_uri_registration").equals(true))
        assertTrue(jsonResponse.getBoolean("claims_parameter_supported").equals(false))
        assertTrue(jsonResponse.getBoolean("backchannel_logout_supported").equals(true))
        assertTrue(jsonResponse.getBoolean("backchannel_logout_session_supported").equals(true))
        assertTrue(jsonResponse.getBoolean("frontchannel_logout_supported").equals(true))
        assertTrue(jsonResponse.getBoolean("frontchannel_logout_session_supported").equals(true))


        assertEquals("authorization_code", jsonResponse.getList("grant_types_supported")[0], "Supported grant types")
        assertEquals("RS256", jsonResponse.getList("id_token_signing_alg_values_supported")[0], "Supported alg values")

        assertEquals((flow.ssoOidcService.baseUrl + "/oauth2/token").toString(), jsonResponse.getString("token_endpoint"), "Correct token endpoint")
        assertEquals((flow.ssoOidcService.baseUrl + "/userinfo").toString(), jsonResponse.getString("userinfo_endpoint"), "Correct userinfo endpoint")
        assertEquals((flow.ssoOidcService.fullAuthenticationRequestUrl).toString(), jsonResponse.getString("authorization_endpoint"), "Correct authorization endpoint")
        assertEquals((flow.ssoOidcService.fullJwksUrl).toString(), jsonResponse.getString("jwks_uri"), "Correct jwks uri")
        assertEquals((flow.ssoOidcService.fullRevocationUrl).toString(), jsonResponse.getString("revocation_endpoint"), "Correct revocation endpoint")
        assertEquals((flow.ssoOidcService.fullLogoutUrl).toString(), jsonResponse.getString("end_session_endpoint"), "Correct session end endpoint")
    }

    @Feature("")
    def "Verify keystore endpoint"() {
        expect:
        JsonPath jsonResponse = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        Response response = Requests.getRequest(jsonResponse.getString("jwks_uri"))
        assertTrue(response.getBody().jsonPath().getString("keys.n").size() > 300, "Correct n size")
        assertTrue(response.getBody().jsonPath().getString("keys.e").size() > 3, "Correct e size")
    }

}
