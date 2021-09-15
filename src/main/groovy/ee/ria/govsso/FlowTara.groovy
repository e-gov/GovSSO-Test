package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import groovy.transform.Canonical
import io.restassured.filter.cookie.CookieFilter
import io.restassured.path.json.JsonPath

@Canonical
class FlowTara {
    Properties properties
    TaraOidcService oidcService
    TaraLoginService loginService
    TaraOidcClient oidcClient
    TaraForeignIdpProvider foreignIdpProvider
    TaraForeignProxyService foreignProxyService

    CookieFilter cookieFilter
    String sessionId
    String login_locale
    String csrf
    String loginChallenge

    String state
    String nonce
    JWKSet jwkSet
    JsonPath openIdServiceConfiguration

    String nextEndpoint
    String requestMessage
    String relayState

    FlowTara(Properties properties) {
        this.properties = properties
        this.loginService = new TaraLoginService(properties)
        this.oidcService = new TaraOidcService(properties)
        this.oidcClient = new TaraOidcClient(properties)
        this.foreignIdpProvider = new TaraForeignIdpProvider(properties)
        this.foreignProxyService = new TaraForeignProxyService(properties)
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
        this.host = properties."oidcservice.host"
        this.port = properties."oidcservice.port"
        this.protocol = properties."oidcservice.protocol"
        this.authenticationRequestUrl = properties."oidcservice.authenticationRequestUrl"
        this.jwksUrl = properties."oidcservice.jwksUrl"
        this.configurationUrl = properties."oidcservice.configurationUrl"
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
            this.host = properties."oidcclient.host"
            this.port = properties."oidcclient.port"
            this.protocol = properties."oidcclient.protocol"
            this.responseUrl = properties."oidcclient.responseUrl"
            this.clientId = properties."oidcclient.clientId"
            this.clientSecret = properties."oidcclient.secret"
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

