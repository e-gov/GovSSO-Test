package ee.ria.govsso

import spock.lang.Shared
import spock.lang.Specification

class GovSsoSpecification extends Specification {
    def static beforeAll = new BeforeAll()

    @Shared
    Properties props = new Properties()
    static String REJECT_ERROR_CODE = "user_cancel"

    def setupSpec() {
        props = beforeAll.props
    }
}