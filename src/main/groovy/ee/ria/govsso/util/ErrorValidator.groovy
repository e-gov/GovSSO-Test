package ee.ria.govsso.util

import ee.ria.govsso.Utils
import ee.ria.govsso.model.ErrorMessage
import io.restassured.http.ContentType
import io.restassured.response.Response
import io.restassured.response.ValidatableResponse

import java.time.ZonedDateTime

import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.hasLength

class ErrorValidator {

    static void validate(Response response, ErrorMessage errorMessage) {
        baseValidate(response, errorMessage)
    }

    static void validate(Response response, ErrorMessage errorMessage, String path) {
        baseValidate(response, errorMessage)
                .body("path", equalTo(path))
    }

    private static ValidatableResponse baseValidate(Response response, ErrorMessage errorMessage) {
        ValidatableResponse validatableResponse = response.then()
                .statusCode(errorMessage.statusCode)
                .contentType(ContentType.JSON)
                .body(
                        "status", equalTo(errorMessage.statusCode),
                        "error", equalTo(errorMessage.errorCode),
                        "message", equalTo(errorMessage.message),
                        "incident_nr", hasLength(32)
                )

        Utils.verifyTimestampAge(ZonedDateTime.parse(response.jsonPath().getString("timestamp")), 10)

        return validatableResponse
    }
}
