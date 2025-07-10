package ee.ria.govsso.configuration

import org.aeonbits.owner.Config

interface SsoOidcDatabaseConf extends Config {
    String protocol()

    String host()

    String port()

    String databaseUrl()

    String username()

    String password()
}
