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

    String clientId
    String loginChallenge
    String logoutChallenge
    String state
    String nonce
    String authCertificate
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
    String nodeHost
    String port
    String nodePort
    String protocol
    String nodeProtocol
    String initUrl
    String logoutInitUrl
    String continueSessionUrl
    String reauthenticateUrl
    String logoutContinueSessionUrl
    String logoutEndSessionUrl
    String loginRejectUrl
    String taraCallbackUrl
    String consentUrl
    String consentConfirmUrl
    String healthUrl
    String readinessUrl
    String livenessUrl
    String infoUrl
    HashMap <String, String> cookies

    @Lazy baseUrl = "${protocol}://${host}"
    @Lazy fullInitUrl = "${protocol}://${host}${initUrl}"
    @Lazy fullLogoutInitUrl = "${protocol}://${host}${logoutInitUrl}"
    @Lazy fullContinueSessionUrl = "${protocol}://${host}${continueSessionUrl}"
    @Lazy fullReauthenticateUrl = "${protocol}://${host}${reauthenticateUrl}"
    @Lazy fullLogoutContinueSessionUrl = "${protocol}://${host}${logoutContinueSessionUrl}"
    @Lazy fullLogoutEndSessionUrl = "${protocol}://${host}${logoutEndSessionUrl}"
    @Lazy fullLoginRejectUrl = "${protocol}://${host}${loginRejectUrl}"
    @Lazy fullTaraCallbackUrl = "${protocol}://${host}${taraCallbackUrl}"
    @Lazy fullConsentUrl = "${protocol}://${host}${consentUrl}"
    @Lazy fullConsentConfirmUrl = "${protocol}://${host}${consentConfirmUrl}"
    @Lazy fullHealthUrl = "${nodeProtocol}://${nodeHost}${portCheck()}${healthUrl}"
    @Lazy fullReadinessUrl = "${nodeProtocol}://${nodeHost}${portCheck()}${readinessUrl}"
    @Lazy fullLivenessUrl = "${nodeProtocol}://${nodeHost}${portCheck()}${livenessUrl}"
    @Lazy fullInfoUrl = "${nodeProtocol}://${nodeHost}${portCheck()}${infoUrl}"

    SsoSessionService(Properties properties) {
        this.host = properties."sessionservice.host"
        this.nodeHost = properties."sessionservice.node.host"
        this.port = properties."sessionservice.port"
        this.nodePort = properties."sessionservice.node.port"
        this.protocol = properties."sessionservice.protocol"
        this.nodeProtocol = properties."sessionservice.node.protocol"
        this.initUrl = properties."sessionservice.initUrl"
        this.logoutInitUrl = properties."sessionservice.logoutInitUrl"
        this.continueSessionUrl = properties."sessionservice.continueSessionUrl"
        this.reauthenticateUrl = properties."sessionservice.reauthenticateUrl"
        this.logoutContinueSessionUrl = properties."sessionservice.logoutContinueSessionUrl"
        this.logoutEndSessionUrl = properties."sessionservice.logoutEndSessionUrl"
        this.loginRejectUrl = properties."sessionservice.loginRejectUrl"
        this.taraCallbackUrl = properties."sessionservice.taraCallbackUrl"
        this.consentUrl = properties."sessionservice.consentUrl"
        this.consentConfirmUrl = properties."sessionservice.consentConfirmUrl"
        this.healthUrl = properties."sessionservice.healthUrl"
        this.readinessUrl = properties."sessionservice.readinessUrl"
        this.livenessUrl = properties."sessionservice.livenessUrl"
        this.infoUrl = properties."sessionservice.infoUrl"
        this.cookies = new HashMap<String, String>()

    }

    private String portCheck() {
        if (nodePort != null && nodePort.isInteger()) {
            return ":${nodePort}"
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

    @Lazy fullAuthenticationRequestUrl = "${protocol}://${host}${authenticationRequestUrl}"
    @Lazy fullLogoutUrl = "${protocol}://${host}${logoutUrl}"
    @Lazy fullJwksUrl = "${protocol}://${host}${jwksUrl}"
    @Lazy fullConfigurationUrl = "${protocol}://${host}${configurationUrl}"
    @Lazy baseUrl = "${protocol}://${host}"

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
    String protocol
    String initUrl
    String midInitUrl
    String midPollUrl
    String webEidInitUrl
    String webEidLoginUrl
    String sidInitUrl
    String sidPollUrl
    String authAcceptUrl
    String authRejectUrl
    String consentUrl
    String consentConfirmUrl
    String authLegalInitUrl
    String authLegalPersonUrl
    String authLegalConfirmUrl
    String eidasInitUrl
    String eidasCallbackUrl
    String idCardEndpointUsername
    String idCardEndpointPassword
    String sessionId
    String login_locale
    String csrf
    HashMap <String, String> cookies
    String taraloginBaseUrl

    @Lazy baseUrl = "${protocol}://${host}"
    @Lazy fullWebEidInitUrl = "${protocol}://${host}${webEidInitUrl}"
    @Lazy fullWebEidLoginUrl = "${protocol}://${host}${webEidLoginUrl}"
    @Lazy fullAuthAcceptUrl = "${protocol}://${host}${authAcceptUrl}"
    @Lazy fullAuthRejectUrl = "${protocol}://${host}${authRejectUrl}"

    TaraService(Properties properties) {
        this.host = properties."taraservice.host"
        this.protocol = properties."taraservice.protocol"
        this.initUrl = properties."taraservice.initUrl"
        this.midInitUrl = properties."taraservice.midInitUrl"
        this.midPollUrl = properties."taraservice.midPollUrl"
        this.webEidInitUrl = properties."taraservice.webEidInitUrl"
        this.webEidLoginUrl = properties."taraservice.webEidLoginUrl"
        this.sidInitUrl = properties."taraservice.sidInitUrl"
        this.sidPollUrl = properties."taraservice.sidPollUrl"
        this.authAcceptUrl = properties."taraservice.authAcceptUrl"
        this.authRejectUrl = properties."taraservice.authRejectUrl"
        this.consentUrl = properties."taraservice.consentUrl"
        this.consentConfirmUrl = properties."taraservice.consentConfirmUrl"
        this.eidasInitUrl = properties."taraservice.eidasInitUrl"
        this.eidasCallbackUrl = properties."taraservice.eidasCallbackUrl"
        this.authLegalInitUrl = properties."taraservice.authLegalInitUrl"
        this.authLegalPersonUrl = properties."taraservice.authLegalPersonUrl"
        this.authLegalConfirmUrl = properties."taraservice.authLegalConfirmUrl"
        this.idCardEndpointUsername = properties."taraservice.id.username"
        this.idCardEndpointPassword = properties."taraservice.id.password"
        this.cookies = new HashMap<String, String>()
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
    String logoutRedirectUrl
    String clientId
    String clientSecret
    String expiredJwt
    HashMap <String, String> cookies

    @Lazy fullBaseUrl = "${protocol}://${host}${portCheck()}"
    @Lazy fullLogoutRedirectUrl = "${protocol}://${host}${portCheck()}${logoutRedirectUrl}"
    @Lazy fullResponseUrl = "${protocol}://${host}${portCheck()}${responseUrl}"

    SsoOidcClientA(Properties properties) {
        this.host = properties."ssooidcclienta.host"
        this.port = properties."ssooidcclienta.port"
        this.protocol = properties."ssooidcclienta.protocol"
        this.responseUrl = properties."ssooidcclienta.responseUrl"
        this.logoutRedirectUrl = properties."ssooidcclienta.logoutRedirectUrl"
        this.clientId = properties."ssooidcclienta.clientId"
        this.clientSecret = properties."ssooidcclienta.secret"
        this.expiredJwt = properties."ssooidcclienta.expiredJwt"
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
    String logoutRedirectUrl
    String clientId
    String clientSecret
    HashMap <String, String> cookies

    @Lazy fullBaseUrl = "${protocol}://${host}${portCheck()}"
    @Lazy fullLogoutRedirectUrl = "${protocol}://${host}${portCheck()}${logoutRedirectUrl}"
    @Lazy fullResponseUrl = "${protocol}://${host}${portCheck()}${responseUrl}"

    SsoOidcClientB(Properties properties) {
        this.host = properties."ssooidcclientb.host"
        this.port = properties."ssooidcclientb.port"
        this.protocol = properties."ssooidcclientb.protocol"
        this.responseUrl = properties."ssooidcclientb.responseUrl"
        this.logoutRedirectUrl = properties."ssooidcclienta.logoutRedirectUrl"
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