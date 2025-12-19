package ee.ria.govsso.configuration

import org.aeonbits.owner.Config

interface SsoInproxyServiceConf extends Config {
    String host()

    String port()

    String protocol()
}
