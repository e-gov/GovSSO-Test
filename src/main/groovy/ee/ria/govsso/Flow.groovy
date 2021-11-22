package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import groovy.transform.Canonical
import io.restassured.filter.cookie.CookieFilter
import io.restassured.path.json.JsonPath

@Canonical
class Flow {
    Properties properties
    SsoSessionService sessionService
    SsoOidcService ssoOidcService
    TaraService taraService
    TaraForeignIdpProvider foreignIdpProvider
    TaraForeignProxyService foreignProxyService
    SsoOidcClientA oidcClientA
    SsoOidcClientB oidcClientB

    CookieFilter cookieFilter

    String loginChallenge

    String state
    String nonce
    JWKSet jwkSet
    JsonPath openIdServiceConfiguration

    String nextEndpoint
    String requestMessage
    String relayState

    Flow(Properties properties) {
        this.properties = properties
        this.sessionService = new SsoSessionService(properties)
        this.ssoOidcService = new SsoOidcService(properties)
        this.taraService = new TaraService(properties)
        this.foreignIdpProvider = new TaraForeignIdpProvider(properties)
        this.foreignProxyService = new TaraForeignProxyService(properties)
        this.oidcClientA = new SsoOidcClientA(properties)
        this.oidcClientB = new SsoOidcClientB(properties)
    }
}

@Canonical
class SsoSessionService {
    String host
    String port
    String protocol
    String initUrl
    String taraCallbackUrl
    String consentUrl
    String consentConfirmUrl
    String healthUrl
    String readinessUrl
    String infoUrl
    HashMap <String, String> cookies

    @Lazy baseUrl = "${protocol}://${host}${portCheck()}"
    @Lazy fullInitUrl = "${protocol}://${host}${portCheck()}${initUrl}"
    @Lazy fullTaraCallbackUrl = "${protocol}://${host}${portCheck()}${taraCallbackUrl}"
    @Lazy fullConsentUrl = "${protocol}://${host}${portCheck()}${consentUrl}"
    @Lazy fullConsentConfirmUrl = "${protocol}://${host}${portCheck()}${consentConfirmUrl}"
    @Lazy fullHealthUrl = "${protocol}://${host}${portCheck()}${healthUrl}"
    @Lazy fullReadinessUrl = "${protocol}://${host}${portCheck()}${readinessUrl}"
    @Lazy fullInfoUrl = "${protocol}://${host}${portCheck()}${infoUrl}"

    SsoSessionService(Properties properties) {
        this.host = properties."sessionservice.host"
        this.port = properties."sessionservice.port"
        this.protocol = properties."sessionservice.protocol"
        this.initUrl = properties."sessionservice.initUrl"
        this.taraCallbackUrl = properties."sessionservice.taraCallbackUrl"
        this.consentUrl = properties."sessionservice.consentUrl"
        this.consentConfirmUrl = properties."sessionservice.consentConfirmUrl"
        this.healthUrl = properties."sessionservice.healthUrl"
        this.readinessUrl = properties."sessionservice.readinessUrl"
        this.infoUrl = properties."sessionservice.infoUrl"
        this.cookies = new HashMap<String, String>()

    }

    private String portCheck() {
        if (port != null && port.isInteger()) {
            return ":${port}"
        } else {
            return ""
        }
    }
}

@Canonical
class SsoOidcService {
    String host
    String port
    String protocol
    String authenticationRequestUrl
    String revocationUrl
    String logoutUrl
    String jwksUrl
    String configurationUrl
    HashMap <String, String> cookies

    @Lazy fullAuthenticationRequestUrl = "${protocol}://${host}${portCheck()}${authenticationRequestUrl}"
    @Lazy fullRevocationUrl = "${protocol}://${host}${portCheck()}${revocationUrl}"
    @Lazy fullLogoutUrl = "${protocol}://${host}${portCheck()}${logoutUrl}"
    @Lazy fullJwksUrl = "${protocol}://${host}${portCheck()}${jwksUrl}"
    @Lazy fullConfigurationUrl = "${protocol}://${host}${portCheck()}${configurationUrl}"
    @Lazy baseUrl = "${protocol}://${host}${portCheck()}"

    SsoOidcService(Properties properties) {
        this.host = properties."ssooidcservice.host"
        this.port = properties."ssooidcservice.port"
        this.protocol = properties."ssooidcservice.protocol"
        this.authenticationRequestUrl = properties."ssooidcservice.authenticationRequestUrl"
        this.revocationUrl = properties."ssooidcservice.revocation"
        this.logoutUrl = properties."ssooidcservice.logout"
        this.jwksUrl = properties."ssooidcservice.jwksUrl"
        this.configurationUrl = properties."ssooidcservice.configurationUrl"
        this.cookies = new HashMap<String, String>()
    }
    private String portCheck() {
        if (port != null && port.isInteger()) {
            return ":${port}"
        } else {
            return ""
        }
    }
}

@Canonical
class TaraService {
    String host
    String port
    String protocol
    String nodeHost
    String nodePort
    String nodeProtocol
    String initUrl
    String midInitUrl
    String midPollUrl
    String midCancelUrl
    String idCardInitUrl
    String sidInitUrl
    String sidPollUrl
    String sidCancelUrl
    String authAcceptUrl
    String authRejectUrl
    String consentUrl
    String consentConfirmUrl
    String heartbeatUrl
    String authLegalInitUrl
    String authLegalPersonUrl
    String authLegalConfirmUrl
    String errorUrl
    String eidasInitUrl
    String eidasCallbackUrl
    String idCardEndpointUsername
    String idCardEndpointPassword
    String sessionId
    String login_locale
    String csrf
    HashMap <String, String> cookies

    @Lazy fullMidInitUrl = "${protocol}://${host}${portCheck()}${midInitUrl}"
    @Lazy fullMidPollUrl = "${protocol}://${host}${portCheck()}${midPollUrl}"
    @Lazy fullIdCardInitUrl = "${nodeProtocol}://${nodeHost}${nodePortCheck()}${idCardInitUrl}"
    @Lazy fullSidInitUrl = "${protocol}://${host}${portCheck()}${sidInitUrl}"
    @Lazy fullSidPollUrl = "${protocol}://${host}${portCheck()}${sidPollUrl}"
    @Lazy fullAuthAcceptUrl = "${protocol}://${host}${portCheck()}${authAcceptUrl}"
    @Lazy fullAuthRejectUrl = "${protocol}://${host}${portCheck()}${authRejectUrl}"
    @Lazy fullConsentConfirmUrl = "${protocol}://${host}${portCheck()}${consentConfirmUrl}"
    @Lazy fullErrorUrl = "${protocol}://${host}${portCheck()}${errorUrl}"
    @Lazy fullEidasInitUrl = "${protocol}://${host}${portCheck()}${eidasInitUrl}"

    TaraService(Properties properties) {
        this.host = properties."taraservice.host"
        this.port = properties."taraservice.port"
        this.protocol = properties."taraservice.protocol"
        this.nodeHost = properties."taraservice.node.host"
        this.nodePort = properties."taraservice.node.port"
        this.nodeProtocol = properties."taraservice.node.protocol"
        this.initUrl = properties."taraservice.initUrl"
        this.midInitUrl = properties."taraservice.midInitUrl"
        this.midPollUrl = properties."taraservice.midPollUrl"
        this.midCancelUrl = properties."taraservice.midCancelUrl"
        this.idCardInitUrl = properties."taraservice.idCardInitUrl"
        this.sidInitUrl = properties."taraservice.sidInitUrl"
        this.sidPollUrl = properties."taraservice.sidPollUrl"
        this.sidCancelUrl = properties."taraservice.sidCancelUrl"
        this.authAcceptUrl = properties."taraservice.authAcceptUrl"
        this.authRejectUrl = properties."taraservice.authRejectUrl"
        this.consentUrl = properties."taraservice.consentUrl"
        this.consentConfirmUrl = properties."taraservice.consentConfirmUrl"
        this.heartbeatUrl = properties."taraservice.heartbeatUrl"
        this.errorUrl = properties."taraservice.errorUrl"
        this.eidasInitUrl = properties."taraservice.eidasInitUrl"
        this.eidasCallbackUrl = properties."taraservice.eidasCallbackUrl"
        this.authLegalInitUrl = properties."taraservice.authLegalInitUrl"
        this.authLegalPersonUrl = properties."taraservice.authLegalPersonUrl"
        this.authLegalConfirmUrl = properties."taraservice.authLegalConfirmUrl"
        this.idCardEndpointUsername = properties."taraservice.id.username"
        this.idCardEndpointPassword = properties."taraservice.id.password"
        this.cookies = new HashMap<String, String>()
    }
    private String portCheck() {
        if (port != null && port.isInteger()) {
            return ":${port}"
        } else {
            return ""
        }
    }

    private String nodePortCheck() {
        if (nodePort != null && nodePort.isInteger()) {
            return ":${nodePort}"
        } else {
            return ""
        }
    }
}

@Canonical
class TaraForeignIdpProvider {
    String host
    String port
    String protocol
    String responseUrl
    @Lazy fullResponseUrl = "${protocol}://${host}${portCheck()}${responseUrl}"

    TaraForeignIdpProvider(Properties properties) {
        this.host = properties."idp.host"
        this.port = properties."idp.port"
        this.protocol = properties."idp.protocol"
        this.responseUrl = properties."idp.responseUrl"
    }
    private String portCheck() {
        if (port != null && port.isInteger()) {
            return ":${port}"
        } else {
            return ""
        }
    }
}

@Canonical
class TaraForeignProxyService {
    String host
    String port
    String protocol
    String consentUrl

    @Lazy fullConsentUrl = "${protocol}://${host}${portCheck()}${consentUrl}"

    TaraForeignProxyService(Properties properties) {
        this.host = properties."ca-proxyservice.host"
        this.port = properties."ca-proxyservice.port"
        this.protocol = properties."ca-proxyservice.protocol"
        this.consentUrl = properties."ca-proxyservice.consentUrl"
    }
    private String portCheck() {
        if (port != null && port.isInteger()) {
            return ":${port}"
        } else {
            return ""
        }
    }
}

@Canonical
class SsoOidcClientA {
    String host
    String port
    String protocol
    String responseUrl
    String requestUrl
    String clientId
    String clientSecret
    HashMap <String, String> cookies

    @Lazy fullResponseUrl = "${protocol}://${host}${portCheck()}${responseUrl}"

    SsoOidcClientA(Properties properties) {
        this.host = properties."ssooidcclienta.host"
        this.port = properties."ssooidcclienta.port"
        this.protocol = properties."ssooidcclienta.protocol"
        this.responseUrl = properties."ssooidcclienta.responseUrl"
        this.clientId = properties."ssooidcclienta.clientId"
        this.clientSecret = properties."ssooidcclienta.secret"
        this.cookies = new HashMap<String, String>()
    }
    private String portCheck() {
        if (port != null && port.isInteger()) {
            return ":${port}"
        } else {
            return ""
        }
    }
}

@Canonical
class SsoOidcClientB {
    String host
    String port
    String protocol
    String responseUrl
    String requestUrl
    String clientId
    String clientSecret
    HashMap <String, String> cookies

    @Lazy fullResponseUrl = "${protocol}://${host}${portCheck()}${responseUrl}"

    SsoOidcClientB(Properties properties) {
        this.host = properties."ssooidcclientb.host"
        this.port = properties."ssooidcclientb.port"
        this.protocol = properties."ssooidcclientb.protocol"
        this.responseUrl = properties."ssooidcclientb.responseUrl"
        this.clientId = properties."ssooidcclientb.clientId"
        this.clientSecret = properties."ssooidcclientb.secret"
        this.cookies = new HashMap<String, String>()
    }
    private String portCheck() {
        if (port != null && port.isInteger()) {
            return ":${port}"
        } else {
            return ""
        }
    }
}