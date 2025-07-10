package ee.ria.govsso.configuration

import org.aeonbits.owner.Config

interface SsoOidcServiceConf extends Config {
    String protocol()

    String host()

    String port()

    String revocation()

    String logout()

    String authenticationRequestUrl()

    String configurationUrl()

    String jwksUrl()
}
