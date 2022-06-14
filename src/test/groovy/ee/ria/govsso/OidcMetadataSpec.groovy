package ee.ria.govsso

import io.qameta.allure.Feature
import io.restassured.path.json.JsonPath
import io.restassured.response.Response

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is

class OidcMetadataSpec extends GovSsoSpecification {

    Flow flow = new Flow(props)

    @Feature("OIDC_DISCOVERY_ENDPOINT")
    def "Verify discovery path"() {
        expect:
        Response configuration = Requests.getRequest(flow.ssoOidcService.fullConfigurationUrl)
        assertThat("Correct HTTP status code", configuration.statusCode(), is(200))
    }

    @Feature("OIDC_DISCOVERY_CONTENT")
    def "Verify discovery content"() {
        expect:
        JsonPath configuration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)

        assertThat("Correct issuer", configuration.getString("issuer"), is(flow.ssoOidcService.baseUrl.toString() + "/"))
        assertThat("Correct authorization endpoint", configuration.getString("authorization_endpoint"), is(flow.ssoOidcService.fullAuthenticationRequestUrl.toString()))
        assertThat("Correct token endpoint", configuration.getString("token_endpoint"), is((flow.ssoOidcService.baseUrl + "/oauth2/token").toString()))
        assertThat("Correct jwks uri", configuration.getString("jwks_uri"), is((flow.ssoOidcService.fullJwksUrl).toString()))
        assertThat("Supported subject type", configuration.getList("subject_types_supported"), is(["public"]))
        assertThat("Supported response type", configuration.getList("response_types_supported"), is(["code"]))
        assertThat("Supported grant type", configuration.getList("grant_types_supported"), is(["authorization_code"]))
        assertThat("Supported response mode", configuration.getList("response_modes_supported"), is(["query"]))
        assertThat("Supported scope", configuration.getList("scopes_supported"), is(["openid", "phone"]))
        assertThat("Correct token endpoint auth method", configuration.getList("token_endpoint_auth_methods_supported"), is(["client_secret_basic"]))
        assertThat("Supported alg values", configuration.getList("id_token_signing_alg_values_supported"), is(["RS256"]))
        assertThat("Correct request_uri_parameter_supported value", configuration.getBoolean("request_uri_parameter_supported") == (false))
        assertThat("Correct claims_parameter_supported value", configuration.getBoolean("claims_parameter_supported") == (false))
        assertThat("Correct backchannel_logout_supported value", configuration.getBoolean("backchannel_logout_supported") == (true))
        assertThat("Correct backchannel_logout_session_supported value", configuration.getBoolean("backchannel_logout_session_supported") == (true))
        assertThat("Supported claim types", configuration.getList("claim_types_supported"), is(["normal"]))
        assertThat("Correct service documentation URL", configuration.getString("service_documentation"), is("https://e-gov.github.io/GOVSSO/"))
        assertThat("Correct service documentation URL", configuration.getString("end_session_endpoint"), is(flow.ssoOidcService.fullLogoutUrl.toString()))

        List<String> claimsSupported = configuration.getList("claims_supported")
        def claimsList = ["sub", "acr", "amr", "at_hash", "aud", "auth_time", "exp", "iat", "iss", "jti", "nonce", "birthdate", "family_name", "given_name", "sid", "phone_number", "phone_number_verified"]
        claimsList.each {
            assertThat("Claims supported. Contains $it", claimsSupported.contains(it))
        }

        List<String> uiLocalesSupported = configuration.getList("ui_locales_supported")
        def uiLocalesList = ["et", "en", "ru"]
        uiLocalesList.each {
            assertThat("UI locales supported. Contains $it", uiLocalesSupported.contains(it))
        }

        List<String> acrValuesSupported = configuration.getList("acr_values_supported")
        def acrValuesList = ["low", "substantial", "high"]
        acrValuesList.each {
            assertThat("Acr values supported. Contains $it", acrValuesSupported.contains(it))
        }
    }

    @Feature("OIDC_ENDPOINTS")
    def "Verify keystore endpoint"() {
        expect:
        JsonPath configuration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        Response jwks = Requests.getRequest(configuration.getString("jwks_uri"))
        assertThat("Correct n size", jwks.getBody().jsonPath().getString("keys.n").size() > 300)
        assertThat("Correct e size", jwks.getBody().jsonPath().getString("keys.e").size() > 3)
    }

}