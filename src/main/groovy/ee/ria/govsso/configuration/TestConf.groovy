package ee.ria.govsso.configuration

import org.aeonbits.owner.Config
import org.aeonbits.owner.Config.Key

interface TestConf extends Config {
    @Key("restAssured.consoleLogging")
    Boolean restAssuredConsoleLogging()

    String deviceLinkMockUrl()
}
