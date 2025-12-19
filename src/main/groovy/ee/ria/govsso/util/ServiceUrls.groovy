package ee.ria.govsso.util

import ee.ria.govsso.*
import ee.ria.govsso.configuration.ConfigHolder

class ServiceUrls {
    static final SsoSessionService SSO_SESSION_SERVICE = new SsoSessionService(ConfigHolder.sessionService)
    static final SsoOidcService SSO_OIDC_SERVICE = new SsoOidcService(ConfigHolder.ssoOidcService)
    static final TaraService TARA_SERVICE = new TaraService(ConfigHolder.taraService)
    static final TaraForeignIdpProvider TARA_FOREIGN_IDP_PROVIDER = new TaraForeignIdpProvider(ConfigHolder.foreignIdp)
    static final TaraForeignProxyService TARA_FOREIGN_PROXY_SERVICE = new TaraForeignProxyService(ConfigHolder.caProxyService)
    static final SsoOidcClient SSO_OIDC_CLIENT_A = new SsoOidcClient(ConfigHolder.ssoOidcClientA)
    static final SsoOidcClient SSO_OIDC_CLIENT_B = new SsoOidcClient(ConfigHolder.ssoOidcClientB)
    static final SsoAdminService SSO_ADMIN_SERVICE = new SsoAdminService(ConfigHolder.ssoAdminServiceConf)
    static final SsoInproxyService SSO_INPROXY_SERVICE = new SsoInproxyService(ConfigHolder.ssoInproxyServiceConf)
}
