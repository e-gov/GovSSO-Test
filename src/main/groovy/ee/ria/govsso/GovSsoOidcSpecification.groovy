package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import io.restassured.filter.cookie.CookieFilter
import io.restassured.path.json.JsonPath
import spock.lang.Shared

/**
 * Base class for specs that exercise OIDC flows and need the discovery metadata and JWKS wired into their flows.
 */
class GovSsoOidcSpecification extends GovSsoSpecification {

    // All tests target the same GovSSO instance, 
    // so fetch discovery and JWKS once per spec class instead of once per test.
    @Shared JsonPath openIdConfiguration
    @Shared JWKSet jwks

    def setupSpec() {
        Flow bootstrapFlow = new Flow()
        openIdConfiguration = Requests.getOpenidConfiguration(bootstrapFlow.ssoOidcService.fullConfigurationUrl)
        jwks = JWKSet.load(Requests.getOpenidJwks(bootstrapFlow.ssoOidcService.fullJwksUrl))
    }

    def setup() {
        wireFlow(flow)
    }

    void wireFlow(Flow flowToWire) {
        flowToWire.cookieFilter = new CookieFilter()
        flowToWire.openIdServiceConfiguration = openIdConfiguration
        flowToWire.jwkSet = jwks
    }
}
