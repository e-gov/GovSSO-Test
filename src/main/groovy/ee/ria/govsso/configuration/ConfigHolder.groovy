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
    private static final SsoOidcClientConf ssoOidcClientA = readConf(SsoOidcClientConf, "ssooidcclienta")
    private static final SsoOidcClientConf ssoOidcClientB = readConf(SsoOidcClientConf, "ssooidcclientb")
    private static final TestConf testConf = readConf(TestConf, "")

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

    static SsoOidcClientConf getSsoOidcClientA() { ssoOidcClientA }

    static SsoOidcClientConf getSsoOidcClientB() { ssoOidcClientB }

    static TestConf getTestConf() { testConf }
}
