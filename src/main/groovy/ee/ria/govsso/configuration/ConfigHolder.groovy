package ee.ria.govsso.configuration

import org.aeonbits.owner.Config
import org.aeonbits.owner.ConfigFactory

class ConfigHolder {

    private static final Properties props = ConfigLoader.load()

    private static final SsoOidcServiceConf ssoOidcService = readConf(SsoOidcServiceConf, "ssooidcservice")
    private static final SsoOidcDatabaseConf ssoOidcDatabase = readConf(SsoOidcDatabaseConf, "ssooidcdatabase")
    private static final SessionServiceConf sessionService = readConf(SessionServiceConf, "sessionservice")
    private static final TaraServiceConf taraService = readConf(TaraServiceConf, "taraservice")
    private static final CaProxyServiceConf caProxyService = readConf(CaProxyServiceConf, "ca-proxyservice")
    private static final ForeignIdpConf foreignIdp = readConf(ForeignIdpConf, "idp")
    private static final InproxyServiceConf inproxyService = readConf(InproxyServiceConf, "inproxyservice")
    private static final AdminServiceConf adminService = readConf(AdminServiceConf, "adminservice")
    private static final EnduserselfserviceConf enduserselfservice = readConf(EnduserselfserviceConf, "enduserselfservice")
    private static final TestConf testConf = readConf(TestConf, "test")

    private static <T extends Config> T readConf(Class<T> configClass) {
        return ConfigFactory.create(configClass, props)
    }

    private static <T extends Config> T readConf(Class<T> configClass, String scope) {
        Properties scoped = new Properties()
        props.each { key, value ->
            if (key.toString().startsWith(scope + ".")) {
                def shortKey = key.toString().replaceFirst("^${scope}\\.", "")
                scoped.put(shortKey, value)
            }
        }
        return ConfigFactory.create(configClass, scoped)
    }

    static SsoOidcServiceConf getSsoOidcService() { ssoOidcService }

    static SsoOidcDatabaseConf getSsoOidcDatabase() { ssoOidcDatabase }

    static SessionServiceConf getSessionService() { sessionService }

    static TaraServiceConf getTaraService() { taraService }

    static CaProxyServiceConf getCaProxyService() { caProxyService }

    static ForeignIdpConf getForeignIdp() { foreignIdp }

    static InproxyServiceConf getInproxyService() { inproxyService }

    static AdminServiceConf getAdminService() { adminService }

    static EnduserselfserviceConf getEnduserselfservice() { enduserselfservice }

    static TestConf getTestConf() { testConf }
}
