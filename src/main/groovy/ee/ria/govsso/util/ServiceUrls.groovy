package ee.ria.govsso.util

import ee.ria.govsso.*
import ee.ria.govsso.configuration.ConfigHolder

class ServiceUrls {
    static final SsoSessionService SESSION_SERVICE = new SsoSessionService(ConfigHolder.sessionService)
    static final SsoOidcService SSO_OIDC_SERVICE = new SsoOidcService(ConfigHolder.ssoOidcService)
    static final InproxyService INPROXY_SERVICE = new InproxyService(ConfigHolder.inproxyService)
    static final AdminService ADMIN_SERVICE = new AdminService(ConfigHolder.adminService)
    static final EnduserselfserviceService ENDUSERSELFSERVICE = new EnduserselfserviceService(ConfigHolder.enduserselfservice)

    static final List<BaseService> SERVICES = [SESSION_SERVICE, SSO_OIDC_SERVICE, INPROXY_SERVICE, ADMIN_SERVICE, ENDUSERSELFSERVICE]

    // In local environments the service URL points directly at a node.
    static boolean isLoadBalancer(BaseService service) {
        List<String> nodeUrls = SERVICES.findAll { it.nodeProtocol && it.nodeHost }*.fullNodeUrl
        !nodeUrls.contains(service.fullBaseUrl)
    }
}
