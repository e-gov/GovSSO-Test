package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll

import static org.hamcrest.Matchers.equalTo
import static org.junit.jupiter.api.Assertions.*

//TODO: add/enable russian translations
class UserInterfaceSpec extends GovSsoSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.ssoOidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.ssoOidcService.fullJwksUrl))
    }

    @Unroll
    @Feature("AUTHENTICATION")
    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Correct buttons with correct form actions exist in session continuation display with specified ui_locales: #uiLocale"() {
        expect:
        Steps.authenticateWithIdCardInGovssoWithUiLocales(flow, uiLocale)
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Response initLogin = Steps.followRedirect(flow, oidcAuth)

        String buttonContinueSession = initLogin.body().htmlPath().getString("**.find { button -> button.@formaction == '/login/continuesession'}")
        String buttonReauthenticate = initLogin.body().htmlPath().getString("**.find { button -> button.@formaction == '/login/reauthenticate'}")
        String buttonReturnToClient = initLogin.body().htmlPath().getString("**.find { button -> button.@formaction == '/login/reject'}")
        assertEquals(continueButton, buttonContinueSession, "Continue button exists with correct form action")
        assertEquals(reauthenticateButton, buttonReauthenticate, "Reauthenticate button exists with correct form action")
        assertEquals(returnButton, buttonReturnToClient, "Return to service provider link exists with correct form action")
        assertTrue(initLogin.body().asString().contains(Utils.getFileAsString("src/test/resources/base64_client_B_logo")), "Correct logo")

        where:
        uiLocale | continueButton     | reauthenticateButton | returnButton
        "et"     | "Jätka seanssi"    | "Autendi uuesti"     | "Tagasi teenusepakkuja juurde"
        "en"     | "Continue session" | "Re-authenticate"    | "Return to service provider"
    }

    @Unroll
    @Feature("LOGOUT")
    def "Correct buttons with correct form actions exist in session logout display with specified ui_locales: #uiLocale"() {
        expect:
        Steps.authenticateWithIdCardInGovssoWithUiLocales(flow, uiLocale)
        Response continueSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueSession.jsonPath().get("id_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, flow.oidcClientB.fullBaseUrl)
        Response initLogout = Steps.followRedirect(flow, oidcLogout)

        String buttonEndSession = initLogout.body().htmlPath().getString("**.find { button -> button.@formaction == '/logout/endsession'}")
        String buttonContinueSession = initLogout.body().htmlPath().getString("**.find { button -> button.@formaction == '/logout/continuesession'}")
        assertEquals(endButton, buttonEndSession, "Reauthenticate button exists with correct form action")
        assertEquals(continueButton, buttonContinueSession, "Continue button exists with correct form action")
        assertTrue(initLogout.body().asString().contains(Utils.getFileAsString("src/test/resources/base64_client_B_logo")), "Correct logo")

        where:
        uiLocale | endButton              | continueButton
        "et"     | "Logi kõikidest välja" | "Jätka seanssi"
        "en"     | "Log out all"          | "Continue session"
    }

    @Unroll
    @Feature("AUTHENTICATION")
    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Correct translations used in session continuation display: translation #uiLocale"() {
        expect:
        Steps.authenticateWithIdCardInGovssoWithUiLocales(flow, uiLocale)

        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Response initLogin = Steps.followRedirect(flow, oidcAuth)

        initLogin.then().body("html.head.title", equalTo(title))

        where:
        uiLocale | title
        "et" | "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        "en" | "National authentication service - Secure authentication for e-services"
//        "ru" | "Национальный сервис аутентификации - Для безопасной аутентификации в э-услугах"
    }

    @Unroll
    @Feature("LOGOUT")
    def "Correct translations used in session logout display: translation #uiLocale"() {
        expect:
        Steps.authenticateWithIdCardInGovssoWithUiLocales(flow, uiLocale)
        Response continueSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueSession.jsonPath().get("id_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, flow.oidcClientB.fullBaseUrl)
        Response initLogout = Steps.followRedirect(flow, oidcLogout)

        initLogout.then().body("html.head.title", equalTo(title))

        where:
        uiLocale | title
        "et"     | "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        "en"     | "National authentication service - Secure authentication for e-services"
//        "ru"     | "Национальный сервис аутентификации - Для безопасной аутентификации в э-услугах"
    }

    @Unroll
    @Feature("LOGOUT")
    def "Correct logout client and active client displayed in logout display with specified ui_locales: #uiLocale"() {
        expect:
        Steps.authenticateWithIdCardInGovssoWithUiLocales(flow, uiLocale)
        Response continueSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueSession.jsonPath().get("id_token")

        Response oidcLogout = Steps.startLogout(flow, idToken, flow.oidcClientB.fullBaseUrl)
        Response initLogout = Steps.followRedirect(flow, oidcLogout)

        assertTrue(initLogout.body().htmlPath().getString("/c-tab-login/*}").contains(logoutText), "Correct logged out client")
        assertTrue(initLogout.body().htmlPath().getString("/c-tab-login/*}").contains(sessionText), "Correct active client")
        assertTrue(initLogout.body().asString().contains(Utils.getFileAsString("src/test/resources/base64_client_B_logo")), "Correct logo")

        where:
        uiLocale | logoutText                                    | sessionText
        "et"     | "Olete välja logitud Teenusenimi B teenusest" | "Olete jätkuvalt sisse logitud järgnevatesse teenustesse:Teenusenimi A"
        "en"     | "You have been logged out from Service name B"| "You are still logged in to the following services:Service name A"
    }

    @Unroll
    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Correct user data displayed in session continuation display"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)
        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Response initLogin = Steps.followRedirect(flow, oidcAuth)

        assertTrue(initLogin.body().htmlPath().getString("/personal-info/*}").contains("JAAK-KRISTJAN"), "Correct first name")
        assertTrue(initLogin.body().htmlPath().getString("/personal-info/*}").contains("JÕEORG"), "Correct surname")
        assertTrue(initLogin.body().htmlPath().getString("/personal-info/*}").contains("EE38001085718"), "Correct personal code")
        assertTrue(initLogin.body().htmlPath().getString("/personal-info/*}").contains("08.01.1980"), "Correct date of birth")
        assertTrue(initLogin.body().asString().contains(Utils.getFileAsString("src/test/resources/base64_client_B_logo")), "Correct logo")
    }

    @Unroll
    @Feature("AUTHENTICATION")
    def "Correct GOVSSO client logo and service name displayed in TARA"() {
        expect:
        Response oidcAuth = Steps.startAuthenticationInSsoOidcWithDefaults(flow)
        Response initLogin = Steps.startSessionInSessionService(flow, oidcAuth)
        Response taraOidcAuth = Steps.followRedirect(flow, initLogin)
        Response taraInitLogin = Steps.followRedirect(flow, taraOidcAuth)
        assertTrue(taraInitLogin.body().asString().contains("Teenusenimi A"), "Correct service name")
        assertTrue(taraInitLogin.body().asString().contains(Utils.getFileAsString("src/test/resources/base64_client_A_logo")), "Correct logo")
    }

    @Feature("LOGIN_INIT_ENDPOINT")
    @Feature("AUTHENTICATION")
    def "Correct buttons with correct form actions exist in session continuation if original acr is lower than expected with specified ui_locales: #uiLocale"() {
        expect:
        Steps.authenticateWithEidasInGovssoWithUiLocales(flow, "substantial", "C", uiLocale)

        Response oidcAuth = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Response initLogin = Steps.followRedirect(flow, oidcAuth)

        String buttonBack = initLogin.body().htmlPath().getString("**.find { button -> button.@formaction == '/login/reject'}")
        String buttonReauthenticate = initLogin.body().htmlPath().getString("**.find { button -> button.@formaction == '/login/reauthenticate'}")

        assertEquals(backButton, buttonBack, "Back button exists with correct form action")
        assertEquals(reauthenticateButton, buttonReauthenticate, "Reauthenticate button exists with correct form action")
        assertTrue(initLogin.body().asString().contains(Utils.getFileAsString("src/test/resources/base64_client_B_logo")), "Correct logo")

        where:
        uiLocale | backButton | reauthenticateButton
        "et"     | "Tagasi"   | "Autendi uuesti"
        "en"     | "Back"     | "Re-authenticate"
    }
}