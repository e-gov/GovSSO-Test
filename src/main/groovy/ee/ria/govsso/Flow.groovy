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

    CookieFilter cookieFilter
    String userAgent
    String ipCountry

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
    }
}

abstract class BaseService {
    String protocol
    String host
    String port

    String nodeProtocol
    String nodeHost
    String nodePort

    @Lazy String baseUrl = "${protocol}://${host}"
    @Lazy String fullBaseUrl = "${baseUrl}${Utils.portCheck(port)}"
    @Lazy String fullNodeUrl = requireUrl("node", nodeProtocol, nodeHost, nodePort)

    BaseService(ServiceConf conf) {
        this.protocol = conf.protocol()
        this.host = conf.host()
        this.port = conf.port()

        if (conf instanceof NodeServiceConf) {
            this.nodeProtocol = conf.nodeProtocol()
            this.nodeHost = conf.nodeHost()
            this.nodePort = conf.nodePort()
        } else {
            this.nodeProtocol = protocol
            this.nodeHost = host
            this.nodePort = port
        }
    }

    protected String requireUrl(String kind, String protocol, String host, String port) {
        if (!protocol || !host) {
            throw new IllegalStateException("${kind.capitalize()} URL is not configured for ${this}: set ${kind}.protocol and ${kind}.host")
        }
        return "${protocol}://${host}${Utils.portCheck(port)}"
    }
}

class SsoSessionService extends BaseService {
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
    String sessionsUrl
    HashMap<String, String> cookies

    @Lazy fullInitUrl = "${baseUrl}${initUrl}"
    @Lazy fullLogoutInitUrl = "${baseUrl}${logoutInitUrl}"
    @Lazy fullContinueSessionUrl = "${baseUrl}${continueSessionUrl}"
    @Lazy fullReauthenticateUrl = "${baseUrl}${reauthenticateUrl}"
    @Lazy fullLogoutContinueSessionUrl = "${baseUrl}${logoutContinueSessionUrl}"
    @Lazy fullLogoutEndSessionUrl = "${baseUrl}${logoutEndSessionUrl}"
    @Lazy fullLoginRejectUrl = "${baseUrl}${loginRejectUrl}"
    @Lazy fullTaraCallbackUrl = "${baseUrl}${taraCallbackUrl}"
    @Lazy fullConsentUrl = "${baseUrl}${consentUrl}"
    @Lazy fullConsentConfirmUrl = "${baseUrl}${consentConfirmUrl}"
    @Lazy baseSessionsUrl = "${fullNodeUrl}${sessionsUrl}"

    SsoSessionService(SessionServiceConf conf) {
        super(conf)
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
        this.sessionsUrl = conf.sessionsUrl()
        this.cookies = new HashMap<String, String>()
    }

    @Override
    String toString() {
        "Session"
    }
}

class SsoOidcService extends BaseService {
    String adminProtocol
    String adminHost
    String adminPort
    String authenticationRequestUrl
    String revocationUrl
    String logoutUrl
    String jwksUrl
    String configurationUrl
    HashMap<String, String> cookies

    @Lazy String fullAdminUrl = requireUrl("admin", adminProtocol, adminHost, adminPort)
    @Lazy fullAuthenticationRequestUrl = "${baseUrl}${authenticationRequestUrl}"
    @Lazy fullLogoutUrl = "${baseUrl}${logoutUrl}"
    @Lazy fullJwksUrl = "${baseUrl}${jwksUrl}"
    @Lazy fullConfigurationUrl = "${baseUrl}${configurationUrl}"

    SsoOidcService(SsoOidcServiceConf conf) {
        super(conf)
        this.adminProtocol = conf.adminProtocol()
        this.adminHost = conf.adminHost()
        this.adminPort = conf.adminPort()
        this.authenticationRequestUrl = conf.authenticationRequestUrl()
        this.revocationUrl = conf.revocation()
        this.logoutUrl = conf.logout()
        this.jwksUrl = conf.jwksUrl()
        this.configurationUrl = conf.configurationUrl()
        this.cookies = new HashMap<String, String>()
    }

    @Override
    String toString() {
        "Hydra"
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

class TaraService extends BaseService {
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

    @Lazy fullWebEidInitUrl = "${baseUrl}${webEidInitUrl}"
    @Lazy fullWebEidLoginUrl = "${baseUrl}${webEidLoginUrl}"
    @Lazy fullAuthAcceptUrl = "${baseUrl}${authAcceptUrl}"
    @Lazy fullAuthRejectUrl = "${baseUrl}${authRejectUrl}"

    TaraService(TaraServiceConf conf) {
        super(conf)
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

    @Override
    String toString() {
        "TARA"
    }
}

class TaraForeignIdpProvider extends BaseService {
    String responseUrl

    @Lazy fullResponseUrl = "${fullBaseUrl}${responseUrl}"

    TaraForeignIdpProvider(ForeignIdpConf conf) {
        super(conf)
        this.responseUrl = conf.responseUrl()
    }
}

class TaraForeignProxyService extends BaseService {
    String consentUrl

    @Lazy fullConsentUrl = "${fullBaseUrl}${consentUrl}"

    TaraForeignProxyService(CaProxyServiceConf conf) {
        super(conf)
        this.consentUrl = conf.consentUrl()
    }
}

class InproxyService extends BaseService {

    InproxyService(InproxyServiceConf conf) {
        super(conf)
    }

    @Override
    String toString() {
        "InProxy"
    }
}

class AdminService extends BaseService {

    AdminService(AdminServiceConf conf) {
        super(conf)
    }

    @Override
    String toString() {
        "Admin"
    }
}

class EnduserselfserviceService extends BaseService {

    EnduserselfserviceService(EnduserselfserviceConf conf) {
        super(conf)
    }

    @Override
    String toString() {
        "EndUserSelfService"
    }
}
