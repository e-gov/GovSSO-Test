package ee.ria.govsso.configuration

import org.aeonbits.owner.Config

interface SsoAdminServiceConf extends Config {
    String host()

    String port()

    String protocol()

    String username()

    String password()
}
