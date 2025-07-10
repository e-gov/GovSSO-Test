package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import ee.ria.govsso.configuration.*
import groovy.transform.Canonical
import io.restassured.filter.cookie.CookieFilter
import io.restassured.path.json.JsonPath

@Canonical
class Flow {
    SsoSessionService sessionService
    SsoOidcService ssoOidcService
    SsoOidcDatabase ssoOidcDatabase
    TaraService taraService
    TaraForeignIdpProvider foreignIdpProvider
    TaraForeignProxyService foreignProxyService
    SsoOidcClient oidcClientA
    SsoOidcClient oidcClientB

    CookieFilter cookieFilter

    String clientId
    String clientSecret
    String loginChallenge
    String logoutChallenge
    String consentChallenge
    String refreshToken
    String idToken
    String state
    String nonce
    String authCertificate
    JWKSet jwkSet
    JsonPath openIdServiceConfiguration

    String nextEndpoint
    String requestMessage
    String relayState

    Flow() {
        this.sessionService = new SsoSessionService(ConfigHolder.sessionService)
        this.ssoOidcService = new SsoOidcService(ConfigHolder.ssoOidcService)
        this.ssoOidcDatabase = new SsoOidcDatabase(ConfigHolder.ssoOidcDatabase)
        this.taraService = new TaraService(ConfigHolder.taraService)
        this.foreignIdpProvider = new TaraForeignIdpProvider(ConfigHolder.foreignIdp)
        this.foreignProxyService = new TaraForeignProxyService(ConfigHolder.caProxyService)
        this.oidcClientA = new SsoOidcClient(ConfigHolder.ssoOidcClientA)
        this.oidcClientB = new SsoOidcClient(ConfigHolder.ssoOidcClientB)
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
    String sessionsUrl
    HashMap<String, String> cookies

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
    @Lazy fullHealthUrl = "${nodeProtocol}://${nodeHost}${Utils.portCheck(nodePort)}${healthUrl}"
    @Lazy fullReadinessUrl = "${nodeProtocol}://${nodeHost}${Utils.portCheck(nodePort)}${readinessUrl}"
    @Lazy fullLivenessUrl = "${nodeProtocol}://${nodeHost}${Utils.portCheck(nodePort)}${livenessUrl}"
    @Lazy fullInfoUrl = "${nodeProtocol}://${nodeHost}${Utils.portCheck(nodePort)}${infoUrl}"
    @Lazy baseSessionsUrl = "${nodeProtocol}://${nodeHost}${Utils.portCheck(nodePort)}${sessionsUrl}"

    SsoSessionService(SessionServiceConf conf) {
        this.host = conf.host()
        this.nodeHost = conf.nodeHost()
        this.port = conf.port()
        this.nodePort = conf.nodePort()
        this.protocol = conf.protocol()
        this.nodeProtocol = conf.nodeProtocol()
        this.initUrl = conf.initUrl()
        this.logoutInitUrl = conf.logoutInitUrl()
        this.continueSessionUrl = conf.continueSessionUrl()
        this.reauthenticateUrl = conf.reauthenticateUrl()
        this.logoutContinueSessionUrl = conf.logoutContinueSessionUrl()
        this.logoutEndSessionUrl = conf.logoutEndSessionUrl()
        this.loginRejectUrl = conf.loginRejectUrl()
        this.taraCallbackUrl = conf.taraCallbackUrl()
        this.consentUrl = conf.consentUrl()
        this.consentConfirmUrl = conf.consentConfirmUrl()
        this.healthUrl = conf.healthUrl()
        this.readinessUrl = conf.readinessUrl()
        this.livenessUrl = conf.livenessUrl()
        this.infoUrl = conf.infoUrl()
        this.sessionsUrl = conf.sessionsUrl()
        this.cookies = new HashMap<String, String>()

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
    HashMap<String, String> cookies

    @Lazy fullAuthenticationRequestUrl = "${protocol}://${host}${authenticationRequestUrl}"
    @Lazy fullLogoutUrl = "${protocol}://${host}${logoutUrl}"
    @Lazy fullJwksUrl = "${protocol}://${host}${jwksUrl}"
    @Lazy fullConfigurationUrl = "${protocol}://${host}${configurationUrl}"
    @Lazy baseUrl = "${protocol}://${host}"

    SsoOidcService(SsoOidcServiceConf conf) {
        this.host = conf.host()
        this.port = conf.port()
        this.protocol = conf.protocol()
        this.authenticationRequestUrl = conf.authenticationRequestUrl()
        this.revocationUrl = conf.revocation()
        this.logoutUrl = conf.logout()
        this.jwksUrl = conf.jwksUrl()
        this.configurationUrl = conf.configurationUrl()
        this.cookies = new HashMap<String, String>()
    }
}

@Canonical
class SsoOidcDatabase {
    String host
    String port
    String protocol
    String databaseUrl
    String username
    String password

    @Lazy fullSsoOidcDatabaseUrl = "${protocol}://${host}${Utils.portCheck(port)}${databaseUrl}"

    SsoOidcDatabase(SsoOidcDatabaseConf conf) {
        this.host = conf.host()
        this.port = conf.port()
        this.protocol = conf.protocol()
        this.databaseUrl = conf.databaseUrl()
        this.username = conf.username()
        this.password = conf.password()
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
    HashMap<String, String> cookies
    String taraloginBaseUrl

    @Lazy baseUrl = "${protocol}://${host}"
    @Lazy fullWebEidInitUrl = "${protocol}://${host}${webEidInitUrl}"
    @Lazy fullWebEidLoginUrl = "${protocol}://${host}${webEidLoginUrl}"
    @Lazy fullAuthAcceptUrl = "${protocol}://${host}${authAcceptUrl}"
    @Lazy fullAuthRejectUrl = "${protocol}://${host}${authRejectUrl}"

    TaraService(TaraServiceConf conf) {
        this.host = conf.host()
        this.protocol = conf.protocol()
        this.initUrl = conf.initUrl()
        this.midInitUrl = conf.midInitUrl()
        this.midPollUrl = conf.midPollUrl()
        this.webEidInitUrl = conf.webEidInitUrl()
        this.webEidLoginUrl = conf.webEidLoginUrl()
        this.sidInitUrl = conf.sidInitUrl()
        this.sidPollUrl = conf.sidPollUrl()
        this.authAcceptUrl = conf.authAcceptUrl()
        this.authRejectUrl = conf.authRejectUrl()
        this.consentUrl = conf.consentUrl()
        this.consentConfirmUrl = conf.consentConfirmUrl()
        this.eidasInitUrl = conf.eidasInitUrl()
        this.eidasCallbackUrl = conf.eidasCallbackUrl()
        this.authLegalInitUrl = conf.authLegalInitUrl()
        this.authLegalPersonUrl = conf.authLegalPersonUrl()
        this.authLegalConfirmUrl = conf.authLegalConfirmUrl()
        this.idCardEndpointUsername = conf.idUsername()
        this.idCardEndpointPassword = conf.idPassword()
        this.cookies = new HashMap<String, String>()
    }
}

@Canonical
class TaraForeignIdpProvider {
    String host
    String port
    String protocol
    String responseUrl

    @Lazy fullResponseUrl = "${protocol}://${host}${Utils.portCheck(port)}${responseUrl}"

    TaraForeignIdpProvider(ForeignIdpConf conf) {
        this.host = conf.host()
        this.port = conf.port()
        this.protocol = conf.protocol()
        this.responseUrl = conf.responseUrl()
    }
}

@Canonical
class TaraForeignProxyService {
    String host
    String port
    String protocol
    String consentUrl

    @Lazy fullConsentUrl = "${protocol}://${host}${Utils.portCheck(port)}${consentUrl}"

    TaraForeignProxyService(CaProxyServiceConf conf) {
        this.host = conf.host()
        this.port = conf.port()
        this.protocol = conf.protocol()
        this.consentUrl = conf.consentUrl()
    }
}

@Canonical
class SsoOidcClient {
    String host
    String port
    String protocol
    String responseUrl
    String logoutRedirectUrl
    String clientId
    String clientSecret
    String expiredJwt
    HashMap<String, String> cookies

    @Lazy fullBaseUrl = "${protocol}://${host}${Utils.portCheck(port)}"
    @Lazy fullLogoutRedirectUrl = "${protocol}://${host}${Utils.portCheck(port)}${logoutRedirectUrl}"
    @Lazy fullResponseUrl = "${protocol}://${host}${Utils.portCheck(port)}${responseUrl}"

    SsoOidcClient(SsoOidcClientConf conf) {
        this.host = conf.host()
        this.port = conf.port()
        this.protocol = conf.protocol()
        this.responseUrl = conf.responseUrl()
        this.logoutRedirectUrl = conf.logoutRedirectUrl()
        this.clientId = conf.clientId()
        this.clientSecret = conf.secret()
        this.expiredJwt = conf.expiredJwt()
        this.cookies = new HashMap<String, String>()
    }
}
