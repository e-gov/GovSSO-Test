package ee.ria.govsso.configuration

import org.aeonbits.owner.Config
import org.aeonbits.owner.Config.Key

interface SsoOidcServiceConf extends Config {
    String protocol()

    String host()

    String port()

    @Key("node.protocol")
    String nodeProtocol()

    @Key("node.host")
    String nodeHost()

    @Key("node.port")
    String nodePort()

    String revocation()

    String logout()

    String authenticationRequestUrl()

    String configurationUrl()

    String jwksUrl()
}
