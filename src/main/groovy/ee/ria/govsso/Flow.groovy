package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import groovy.transform.Canonical
import io.restassured.filter.cookie.CookieFilter
import io.restassured.path.json.JsonPath

@Canonical
class Flow {
    Properties properties
    SsoSessionService sessionService
    TaraOidcService taraOidcService
    SsoOidcService ssoOidcService
    TaraLoginService taraLoginService
    TaraOidcClient oidcClient
    SsoOidcClientA oidcClientA
    SsoOidcClientB oidcClientB
    TaraForeignIdpProvider foreignIdpProvider
    TaraForeignProxyService foreignProxyService

    CookieFilter cookieFilter

    String csrf
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
        this.taraLoginService = new TaraLoginService(properties)
        this.taraOidcService = new TaraOidcService(properties)
        this.ssoOidcService = new SsoOidcService(properties)
        this.oidcClient = new TaraOidcClient(properties)
        this.oidcClientA = new SsoOidcClientA(properties)
        this.oidcClientB = new SsoOidcClientB(properties)
        this.foreignIdpProvider = new TaraForeignIdpProvider(properties)
        this.foreignProxyService = new TaraForeignProxyService(properties)
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
class TaraLoginService {
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

    @Lazy fullInitUrl = "${protocol}://${host}${portCheck()}${initUrl}"
    @Lazy fullMidInitUrl = "${protocol}://${host}${portCheck()}${midInitUrl}"
    @Lazy fullMidPollUrl = "${protocol}://${host}${portCheck()}${midPollUrl}"
    @Lazy fullMidCancelUrl = "${protocol}://${host}${portCheck()}${midCancelUrl}"
    @Lazy fullIdCardInitUrl = "${nodeProtocol}://${nodeHost}${nodePortCheck()}${idCardInitUrl}"
    @Lazy fullSidInitUrl = "${protocol}://${host}${portCheck()}${sidInitUrl}"
    @Lazy fullSidPollUrl = "${protocol}://${host}${portCheck()}${sidPollUrl}"
    @Lazy fullSidCancelUrl = "${protocol}://${host}${portCheck()}${sidCancelUrl}"
    @Lazy fullAuthAcceptUrl = "${protocol}://${host}${portCheck()}${authAcceptUrl}"
    @Lazy fullAuthRejectUrl = "${protocol}://${host}${portCheck()}${authRejectUrl}"
    @Lazy fullConsentUrl = "${protocol}://${host}${portCheck()}${consentUrl}"
    @Lazy fullConsentConfirmUrl = "${protocol}://${host}${portCheck()}${consentConfirmUrl}"
    @Lazy fullHeartbeatUrl = "${nodeProtocol}://${nodeHost}${nodePortCheck()}${heartbeatUrl}"
    @Lazy fullErrorUrl = "${protocol}://${host}${portCheck()}${errorUrl}"
    @Lazy fullEidasInitUrl = "${protocol}://${host}${portCheck()}${eidasInitUrl}"
    @Lazy fullEidasCallbackUrl = "${protocol}://${host}${portCheck()}${eidasCallbackUrl}"
    @Lazy fullAuthLegalInitUrl = "${protocol}://${host}${portCheck()}${authLegalInitUrl}"
    @Lazy fullAuthLegalPersonUrl = "${protocol}://${host}${portCheck()}${authLegalPersonUrl}"
    @Lazy fullAuthLegalConfirmUrl = "${protocol}://${host}${portCheck()}${authLegalConfirmUrl}"
    @Lazy baseUrl = "${protocol}://${host}${portCheck()}"

    TaraLoginService(Properties properties) {
        this.host = properties."loginservice.host"
        this.port = properties."loginservice.port"
        this.protocol = properties."loginservice.protocol"
        this.nodeHost = properties."loginservice.node.host"
        this.nodePort = properties."loginservice.node.port"
        this.nodeProtocol = properties."loginservice.node.protocol"
        this.initUrl = properties."loginservice.initUrl"
        this.midInitUrl = properties."loginservice.midInitUrl"
        this.midPollUrl = properties."loginservice.midPollUrl"
        this.midCancelUrl = properties."loginservice.midCancelUrl"
        this.idCardInitUrl = properties."loginservice.idCardInitUrl"
        this.sidInitUrl = properties."loginservice.sidInitUrl"
        this.sidPollUrl = properties."loginservice.sidPollUrl"
        this.sidCancelUrl = properties."loginservice.sidCancelUrl"
        this.authAcceptUrl = properties."loginservice.authAcceptUrl"
        this.authRejectUrl = properties."loginservice.authRejectUrl"
        this.consentUrl = properties."loginservice.consentUrl"
        this.consentConfirmUrl = properties."loginservice.consentConfirmUrl"
        this.heartbeatUrl = properties."loginservice.heartbeatUrl"
        this.errorUrl = properties."loginservice.errorUrl"
        this.eidasInitUrl = properties."loginservice.eidasInitUrl"
        this.eidasCallbackUrl = properties."loginservice.eidasCallbackUrl"
        this.authLegalInitUrl = properties."loginservice.authLegalInitUrl"
        this.authLegalPersonUrl = properties."loginservice.authLegalPersonUrl"
        this.authLegalConfirmUrl = properties."loginservice.authLegalConfirmUrl"
        this.idCardEndpointUsername = properties."loginservice.id.username"
        this.idCardEndpointPassword = properties."loginservice.id.password"
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
class TaraOidcService {
    String host
    String port
    String protocol
    String authenticationRequestUrl
    String jwksUrl
    String configurationUrl
    HashMap <String, String> cookies

    @Lazy fullAuthenticationRequestUrl = "${protocol}://${host}${portCheck()}${authenticationRequestUrl}"
    @Lazy fullJwksUrl = "${protocol}://${host}${portCheck()}${jwksUrl}"
    @Lazy fullConfigurationUrl = "${protocol}://${host}${portCheck()}${configurationUrl}"
    @Lazy baseUrl = "${protocol}://${host}${portCheck()}"

    TaraOidcService(Properties properties) {
        this.host = properties."taraoidcservice.host"
        this.port = properties."taraoidcservice.port"
        this.protocol = properties."taraoidcservice.protocol"
        this.authenticationRequestUrl = properties."taraoidcservice.authenticationRequestUrl"
        this.jwksUrl = properties."taraoidcservice.jwksUrl"
        this.configurationUrl = properties."taraoidcservice.configurationUrl"
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
class TaraOidcClient {
    String host
    String port
    String protocol
    String responseUrl
    String requestUrl
    String clientId
    String clientSecret
    HashMap <String, String> cookies

    @Lazy fullResponseUrl = "${protocol}://${host}${portCheck()}${responseUrl}"

    TaraOidcClient(Properties properties) {
        this.host = properties."taraoidcclient.host"
        this.port = properties."taraoidcclient.port"
        this.protocol = properties."taraoidcclient.protocol"
        this.responseUrl = properties."taraoidcclient.responseUrl"
        this.clientId = properties."taraoidcclient.clientId"
        this.clientSecret = properties."taraoidcclient.secret"
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