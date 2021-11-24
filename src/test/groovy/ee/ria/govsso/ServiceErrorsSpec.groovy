package ee.ria.govsso

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import spock.lang.Ignore


@Ignore
class ServiceErrorsSpec extends GovSsoSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Ignore
    @Feature("")
    def "Filter service errors for end user: #inputValue"() {

    }

    @Ignore
    @Feature("")
    def "Verify error response json"() {

    }

    @Ignore
    @Feature("")
    def "Verify error response html: general error"() {

    }

    @Ignore
    @Feature("")
    def "Verify error response html: invalid client"() {

    }


}
