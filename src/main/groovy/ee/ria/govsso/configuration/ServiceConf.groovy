package ee.ria.govsso.configuration

import org.aeonbits.owner.Config

interface ServiceConf extends Config {
    String protocol()

    String host()

    String port()
}
