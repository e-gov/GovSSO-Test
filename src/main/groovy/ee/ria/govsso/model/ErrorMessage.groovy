package ee.ria.govsso.model

import org.apache.http.HttpStatus

enum ErrorMessage {

    USER_INPUT(HttpStatus.SC_BAD_REQUEST, "Ebakorrektne päring."),
    FORBIDDEN_USER_INPUT(HttpStatus.SC_FORBIDDEN, "Ebakorrektne päring.") {
        // GovSSO maps every 4xx it does not raise itself to USER_INPUT.
        @Override
        String getErrorCode() { return USER_INPUT.errorCode }
    },
    USER_INPUT_OR_EXPIRED(HttpStatus.SC_BAD_REQUEST, "Ebakorrektne päring või päring aegus. Palun minge tagasi teenusepakkuja juurde ja proovige uuesti."),
    USER_COOKIE_MISSING(HttpStatus.SC_BAD_REQUEST, "Küpsis on puudu või kehtivuse kaotanud"),
    USER_INVALID_OIDC_CLIENT(HttpStatus.SC_BAD_REQUEST, "Vale <span translate=\"no\">OIDC</span> klient."),
    USER_INVALID_OIDC_REQUEST(HttpStatus.SC_BAD_REQUEST, "Vale <span translate=\"no\">OIDC</span> päring."),
    USER_OIDC_OTHER_ERROR(HttpStatus.SC_INTERNAL_SERVER_ERROR, "Vale <span translate=\"no\">OIDC</span> päring."),
    TECHNICAL_TARA_UNAVAILABLE(HttpStatus.SC_INTERNAL_SERVER_ERROR, "<span translate=\"no\">TARA</span> teenus ei ole kättesaadav. Palun proovige mõne aja pärast uuesti."),
    TECHNICAL_GENERAL(HttpStatus.SC_INTERNAL_SERVER_ERROR, "Protsess ebaõnnestus tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."),

    final int statusCode
    final String message

    ErrorMessage(int statusCode, String message) {
        this.statusCode = statusCode
        this.message = message
    }

    String getErrorCode() {
        return name()
    }

    String toString() {
        return message
    }
}
