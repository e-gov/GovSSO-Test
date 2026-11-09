package ee.ria.govsso.model

import org.apache.http.HttpStatus

// OAuth 2.0 errors returned by Ory Hydra. The error_description is the description below, followed by a hint.
enum HydraError {

    INVALID_REQUEST(HttpStatus.SC_BAD_REQUEST, "invalid_request", "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."),
    INVALID_GRANT(HttpStatus.SC_BAD_REQUEST, "invalid_grant", "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client."),
    INVALID_CLIENT(HttpStatus.SC_UNAUTHORIZED, "invalid_client", "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)."),
    TOKEN_INACTIVE(HttpStatus.SC_UNAUTHORIZED, "token_inactive", "Token is inactive because it is malformed, expired or otherwise invalid."),
    INVALID_SCOPE(HttpStatus.SC_BAD_REQUEST, "invalid_scope", "The requested scope is invalid, unknown, or malformed."),
    INVALID_STATE(HttpStatus.SC_BAD_REQUEST, "invalid_state", "The state is missing or does not have enough characters and is therefore considered too weak."),
    UNSUPPORTED_RESPONSE_TYPE(HttpStatus.SC_BAD_REQUEST, "unsupported_response_type", "The authorization server does not support obtaining a token using this method."),
    LOGIN_REQUIRED(HttpStatus.SC_BAD_REQUEST, "login_required", "The Authorization Server requires End-User authentication."),
    ACCESS_DENIED(HttpStatus.SC_FORBIDDEN, "access_denied", "The resource owner or authorization server denied the request."),
    // Token request rejected by the GovSSO token hook. Hydra returns only the hook's reason, without a description of its own.
    TOKEN_HOOK_REJECTION(HttpStatus.SC_BAD_REQUEST, "invalid_request", ""),
    // Login rejection by GovSSO (and TARA), passed through by Hydra.
    USER_CANCEL(HttpStatus.SC_BAD_REQUEST, "user_cancel", "User canceled the authentication process."),

    final int statusCode
    final String code
    final String description

    HydraError(int statusCode, String code, String description) {
        this.statusCode = statusCode
        this.code = code
        this.description = description
    }

    String toString() {
        return code
    }
}
