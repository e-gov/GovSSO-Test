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
    SsoAdminService adminService
    SsoInproxyService inproxyService

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
        this.adminService = new SsoAdminService(ConfigHolder.ssoAdminServiceConf)
        this.inproxyService = new SsoInproxyService(ConfigHolder.ssoInproxyServiceConf)
    }
}

@Canonical
abstract class BaseService {
    String protocol
    String host
    String port

    String nodeProtocol
    String nodeHost
    String nodePort

    @Lazy baseUrl = "${protocol}://${host}"
    @Lazy fullBaseUrl = "${baseUrl}${Utils.portCheck(port)}"
    @Lazy fullNodeUrl = "${nodeProtocol}://${nodeHost}${Utils.portCheck(nodePort)}"

    BaseService(conf) {
        this.protocol = conf.protocol()
        this.host = conf.host()
        this.port = conf.port()

        switch (conf) {
            case ForeignIdpConf: // fall through
            case CaProxyServiceConf: // fall through
            case SsoOidcClientConf: // fall through
            case SsoOidcDatabaseConf: // fall through
            case SsoAdminServiceConf: // fall through
            case SsoInproxyServiceConf:
                this.nodeProtocol = this.protocol
                this.nodeHost = this.host
                this.nodePort = this.port
                break
            default:
                this.nodeProtocol = conf.nodeProtocol()
                this.nodeHost = conf.nodeHost()
                this.nodePort = conf.nodePort()
        }
    }
}

@Canonical
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
        return "Session service"
    }
}

@Canonical
class SsoOidcService extends BaseService {
    String authenticationRequestUrl
    String revocationUrl
    String logoutUrl
    String jwksUrl
    String configurationUrl
    HashMap<String, String> cookies

    @Lazy fullAuthenticationRequestUrl = "${baseUrl}${authenticationRequestUrl}"
    @Lazy fullLogoutUrl = "${baseUrl}${logoutUrl}"
    @Lazy fullJwksUrl = "${baseUrl}${jwksUrl}"
    @Lazy fullConfigurationUrl = "${baseUrl}${configurationUrl}"
    @Lazy fullNodeUrlPrometheus = "${nodeProtocol}://${nodeHost}${Utils.portCheck("4445")}"

    SsoOidcService(SsoOidcServiceConf conf) {
        super(conf)
        this.authenticationRequestUrl = conf.authenticationRequestUrl()
        this.revocationUrl = conf.revocation()
        this.logoutUrl = conf.logout()
        this.jwksUrl = conf.jwksUrl()
        this.configurationUrl = conf.configurationUrl()
        this.cookies = new HashMap<String, String>()
    }

    @Override
    String toString() {
        return "OIDC service"
    }
}

@Canonical
class SsoOidcDatabase extends BaseService{
    String databaseUrl
    String username
    String password

    @Lazy fullSsoOidcDatabaseUrl = "${fullBaseUrl}${databaseUrl}"

    SsoOidcDatabase(SsoOidcDatabaseConf conf) {
        super(conf)
        this.databaseUrl = conf.databaseUrl()
        this.username = conf.username()
        this.password = conf.password()
    }
}

@Canonical
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
}

@Canonical
class TaraForeignIdpProvider extends BaseService {
    String responseUrl

    @Lazy fullResponseUrl = "${fullBaseUrl}${responseUrl}"

    TaraForeignIdpProvider(ForeignIdpConf conf) {
        super(conf)
        this.responseUrl = conf.responseUrl()
    }
}

@Canonical
class TaraForeignProxyService extends BaseService {
    String consentUrl

    @Lazy fullConsentUrl = "${fullBaseUrl}${consentUrl}"

    TaraForeignProxyService(CaProxyServiceConf conf) {
        super(conf)
        this.consentUrl = conf.consentUrl()
    }
}

@Canonical
class SsoOidcClient extends BaseService{
    String responseUrl
    String logoutRedirectUrl
    String clientId
    String clientSecret
    String expiredJwt
    HashMap<String, String> cookies

    @Lazy fullLogoutRedirectUrl = "${fullBaseUrl}${logoutRedirectUrl}"
    @Lazy fullResponseUrl = "${fullBaseUrl}${responseUrl}"

    SsoOidcClient(SsoOidcClientConf conf) {
        super(conf)
        this.responseUrl = conf.responseUrl()
        this.logoutRedirectUrl = conf.logoutRedirectUrl()
        this.clientId = conf.clientId()
        this.clientSecret = conf.secret()
        this.expiredJwt = conf.expiredJwt()
        this.cookies = new HashMap<String, String>()
    }
}

@Canonical
class SsoAdminService extends BaseService{
    String username
    String password

    SsoAdminService(SsoAdminServiceConf conf) {
        super(conf)
        this.username = conf.username()
        this.password = conf.password()
    }

    @Override
    String toString() {
        return "GovSSO Admin"
    }
}

@Canonical
class SsoInproxyService extends BaseService {

    SsoInproxyService(SsoInproxyServiceConf conf) {
        super(conf)
    }

    @Override
    String toString() {
        return "Inproxy service"
    }
}
