package ee.ria.govsso.configuration

import org.aeonbits.owner.Config.Key

interface NodeServiceConf extends ServiceConf {
    @Key("node.protocol")
    String nodeProtocol()

    @Key("node.host")
    String nodeHost()

    @Key("node.port")
    String nodePort()
}
