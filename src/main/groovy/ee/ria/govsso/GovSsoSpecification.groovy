package ee.ria.govsso


import spock.lang.Specification

class GovSsoSpecification extends Specification {
    static {
        new BeforeAll()
    }

    Flow flow = new Flow()

    static String REJECT_ERROR_CODE = "user_cancel"
}
