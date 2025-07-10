package ee.ria.govsso.configuration

import org.aeonbits.owner.Config
import org.aeonbits.owner.Config.Key

interface SessionServiceConf extends Config {
    String protocol()

    String host()

    String port()

    String initUrl()

    String logoutInitUrl()

    String continueSessionUrl()

    String reauthenticateUrl()

    String logoutContinueSessionUrl()

    String logoutEndSessionUrl()

    String loginRejectUrl()

    String consentUrl()

    String consentConfirmUrl()

    String taraCallbackUrl()

    String healthUrl()

    String readinessUrl()

    String livenessUrl()

    String infoUrl()

    String sessionsUrl()

    @Key("node.protocol")
    String nodeProtocol()

    @Key("node.host")
    String nodeHost()

    @Key("node.port")
    String nodePort()
}
