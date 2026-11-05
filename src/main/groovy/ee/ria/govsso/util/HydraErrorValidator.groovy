package ee.ria.govsso.util

import ee.ria.govsso.Utils
import ee.ria.govsso.model.HydraError
import io.restassured.http.ContentType
import io.restassured.response.Response
import org.hamcrest.Matcher

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.emptyString
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.startsWith

class HydraErrorValidator {

    static final String HINT_SESSION_EXPIRED = "Authentication session not found or expired."
    static final String HINT_TOKEN_VALIDATION_FAILED = "Token validation failed."

    static void validate(Response response, HydraError error) {
        validate(response, error, emptyString())
    }

    static void validate(Response response, HydraError error, String hint) {
        validate(response, error, equalTo(hint))
    }

    static void validate(Response response, HydraError error, Matcher<? super String> hint) {
        response.then()
                .statusCode(error.statusCode)
                .contentType(ContentType.JSON)
                .body("error", equalTo(error.code))

        validateDescription(response.jsonPath().getString("error_description"), error, hint)
    }

    static void validateRedirect(Response response, HydraError error) {
        validateRedirect(response, error, emptyString())
    }

    static void validateRedirect(Response response, HydraError error, String hint) {
        validateRedirect(response, error, equalTo(hint))
    }

    // The error is returned in the query of the redirect location.
    static void validateRedirect(Response response, HydraError error, Matcher<? super String> hint) {
        assertThat("Correct error", Utils.getParamValueFromResponseHeader(response, "error"), equalTo(error.code))

        validateDescription(Utils.getParamValueFromResponseHeader(response, "error_description"), error, hint)
    }

    // Hint of the invalid_request error for a requested audience that is not whitelisted for the client.
    static String notWhitelisted(String audience) {
        return "Requested audience '${audience}' has not been whitelisted by the OAuth 2.0 Client."
    }

    // Hint of the invalid_scope error for a scope that the client is not allowed to request.
    static String scopeNotAllowed(String scope) {
        return "The OAuth 2.0 Client is not allowed to request scope '${scope}'."
    }

    // Hint of the unsupported_response_type error for a response type that the client is not allowed to request.
    static String responseTypeNotAllowed(String responseType) {
        return "The client is not allowed to request response_type '${responseType}'."
    }

    // Part of the invalid_client hint for a token request that uses another authentication method than the client's.
    static String authMethodNotSupported(String supported, String requested) {
        return "The OAuth 2.0 Client supports client authentication method '${supported}', but method '${requested}' was requested."
    }

    private static void validateDescription(String errorDescription, HydraError error, Matcher<? super String> hint) {
        assertThat("Error description starts with the description of " + error.code, errorDescription, startsWith(error.description))
        assertThat("Correct error hint", errorDescription.substring(error.description.length()).trim(), hint)
    }
}
