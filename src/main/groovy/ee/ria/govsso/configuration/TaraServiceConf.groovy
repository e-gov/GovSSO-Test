package ee.ria.govsso.configuration

import org.aeonbits.owner.Config
import org.aeonbits.owner.Config.Key

interface TaraServiceConf extends Config {
    String protocol()

    String host()

    String port()

    String initUrl()

    String midInitUrl()

    String midPollUrl()

    String webEidInitUrl()

    String webEidLoginUrl()

    String sidInitUrl()

    String sidPollUrl()

    String authAcceptUrl()

    String authRejectUrl()

    String eidasInitUrl()

    String eidasCallbackUrl()

    String authLegalInitUrl()

    String authLegalPersonUrl()

    String authLegalConfirmUrl()

    String consentUrl()

    String consentConfirmUrl()

    @Key("id.username")
    String idUsername()

    @Key("id.password")
    String idPassword()

    @Key("node.protocol")
    String nodeProtocol()

    @Key("node.host")
    String nodeHost()

    @Key("node.port")
    String nodePort()
}
