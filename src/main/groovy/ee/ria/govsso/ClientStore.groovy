package ee.ria.govsso

import com.fasterxml.jackson.databind.ObjectMapper
import ee.ria.govsso.configuration.ConfigHolder
import ee.ria.govsso.model.Client

import java.nio.file.Path
import java.nio.file.Paths

class ClientStore {

    @Lazy
    static Client clientA = readClientJson("client-a")

    @Lazy
    static Client clientB = readClientJson("client-b")

    @Lazy
    static Client mockSecuredApp = readClientJson("client-mock-secured-app")

    @Lazy
    static Client mockAcrLow = readClientJson("client-mock-acr-low")

    @Lazy
    static Client mockAcrSubstantial = readClientJson("client-mock-acr-substantial")

    @Lazy
    static Client mockAcrHigh = readClientJson("client-mock-acr-high")

    static Client readClientJson(String fileName) {
        Path filePath = Paths.get(ConfigHolder.testConf.adminSetupPath(), "${fileName}.json")
        return new ObjectMapper().readValue(filePath.toFile(), Client)
    }
}
