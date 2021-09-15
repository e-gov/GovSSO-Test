package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import groovy.transform.Canonical
import io.restassured.filter.cookie.CookieFilter
import io.restassured.path.json.JsonPath

@Canonical
class FlowGovSso {
    Properties properties
    OidcService oidcService
    SessionService sessionService
    OidcClient oidcClient

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

    FlowGovSso(Properties properties) {
        this.properties = properties
        this.sessionService = new SessionService(properties)
        this.oidcService = new OidcService(properties)
        this.oidcClient = new OidcClient(properties)
    }
}

@Canonical
class SessionService {
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

    SessionService(Properties properties) {
        this.host = properties."sessionservice.host"
        this.port = properties."sessionservice.port"
        this.protocol = properties."sessionservice.protocol"
        this.nodeHost = properties."sessionservice.node.host"
        this.nodePort = properties."sessionservice.node.port"
        this.nodeProtocol = properties."sessionservice.node.protocol"
        this.initUrl = properties."sessionservice.initUrl"
        this.midInitUrl = properties."sessionservice.midInitUrl"
        this.midPollUrl = properties."sessionservice.midPollUrl"
        this.midCancelUrl = properties."sessionservice.midCancelUrl"
        this.idCardInitUrl = properties."sessionservice.idCardInitUrl"
        this.sidInitUrl = properties."sessionservice.sidInitUrl"
        this.sidPollUrl = properties."sessionservice.sidPollUrl"
        this.sidCancelUrl = properties."sessionservice.sidCancelUrl"
        this.authAcceptUrl = properties."sessionservice.authAcceptUrl"
        this.authRejectUrl = properties."sessionservice.authRejectUrl"
        this.consentUrl = properties."sessionservice.consentUrl"
        this.consentConfirmUrl = properties."sessionservice.consentConfirmUrl"
        this.heartbeatUrl = properties."sessionservice.heartbeatUrl"
        this.errorUrl = properties."sessionservice.errorUrl"
        this.eidasInitUrl = properties."sessionservice.eidasInitUrl"
        this.eidasCallbackUrl = properties."sessionservice.eidasCallbackUrl"
        this.authLegalInitUrl = properties."sessionservice.authLegalInitUrl"
        this.authLegalPersonUrl = properties."sessionservice.authLegalPersonUrl"
        this.authLegalConfirmUrl = properties."sessionservice.authLegalConfirmUrl"
        this.idCardEndpointUsername = properties."sessionservice.id.username"
        this.idCardEndpointPassword = properties."sessionservice.id.password"
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
class OidcService {
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

    OidcService(Properties properties) {
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
    class OidcClient {
        String host
        String port
        String protocol
        String responseUrl
        String requestUrl
        String clientId
        String clientSecret
        HashMap <String, String> cookies

        @Lazy fullResponseUrl = "${protocol}://${host}${portCheck()}${responseUrl}"

        OidcClient(Properties properties) {
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

