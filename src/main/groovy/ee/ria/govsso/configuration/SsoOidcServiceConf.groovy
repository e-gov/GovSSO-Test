package ee.ria.govsso.configuration

import org.aeonbits.owner.Config.Key

interface SsoOidcServiceConf extends NodeServiceConf {
    String revocation()

    String logout()

    String authenticationRequestUrl()

    String configurationUrl()

    String jwksUrl()

    @Key("admin.protocol")
    String adminProtocol()

    @Key("admin.host")
    String adminHost()

    @Key("admin.port")
    String adminPort()
}
