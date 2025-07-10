package ee.ria.govsso.configuration

import org.aeonbits.owner.Config

interface SsoOidcClientConf extends Config {
    String protocol()

    String host()

    String port()

    String responseUrl()

    String logoutRedirectUrl()

    String clientId()

    String secret()

    String expiredJwt()
}
