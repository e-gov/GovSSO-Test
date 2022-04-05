package ee.ria.govsso

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll

import static org.hamcrest.Matchers.equalTo
import static org.junit.jupiter.api.Assertions.*


//TODO: add russian translations
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
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Response initLoginResponse = Steps.followRedirect(flow, oidcServiceInitResponse)

        String buttonContinueSession = initLoginResponse.body().htmlPath().getString("**.find { button -> button.@formaction == '/login/continuesession'}")
        String buttonReauthenticate = initLoginResponse.body().htmlPath().getString("**.find { button -> button.@formaction == '/login/reauthenticate'}")
        String buttonReturnToClient = initLoginResponse.body().htmlPath().getString("**.find { button -> button.@formaction == '/login/reject'}")
        assertEquals(continueButton, buttonContinueSession, "Continue button exists with correct form action")
        assertEquals(reauthenticateButton, buttonReauthenticate, "Reauthenticate button exists with correct form action")
        assertEquals(returnButton, buttonReturnToClient, "Return to service provider link exists with correct form action")

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
        Response continueWithExistingSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueWithExistingSession.jsonPath().get("id_token")

        Response initLogoutOidc = Steps.startLogout(flow, idToken, flow.oidcClientB.fullBaseUrl)
        Response initLogoutSession = Steps.followRedirect(flow, initLogoutOidc)

        String buttonEndSession = initLogoutSession.body().htmlPath().getString("**.find { button -> button.@formaction == '/logout/endsession'}")
        String buttonContinueSession = initLogoutSession.body().htmlPath().getString("**.find { button -> button.@formaction == '/logout/continuesession'}")
        assertEquals(endButton, buttonEndSession, "Reauthenticate button exists with correct form action")
        assertEquals(continueButton, buttonContinueSession, "Continue button exists with correct form action")

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

        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Response loginInit = Steps.followRedirect(flow, oidcServiceInitResponse)

        loginInit.then().body("html.head.title", equalTo(title))

        where:
        uiLocale | title
        "et" | "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        "en" | "National authentication service - Secure authentication for e-services"
        "ru" | "Национальный сервис аутентификации - Для безопасной аутентификации в э-услугах"
    }

    @Unroll
    @Feature("LOGOUT")
    def "Correct translations used in session logout display: translation #uiLocale"() {
        expect:
        Steps.authenticateWithIdCardInGovssoWithUiLocales(flow, uiLocale)
        Response continueWithExistingSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueWithExistingSession.jsonPath().get("id_token")

        Response initLogoutOidc = Steps.startLogout(flow, idToken, flow.oidcClientB.fullBaseUrl)
        Response initLogoutSession = Steps.followRedirect(flow, initLogoutOidc)

        initLogoutSession.then().body("html.head.title", equalTo(title))

        where:
        uiLocale | title
        "et"     | "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        "en"     | "National authentication service - Secure authentication for e-services"
        "ru"     | "Национальный сервис аутентификации - Для безопасной аутентификации в э-услугах"
    }

    @Unroll
    @Feature("LOGOUT")
    def "Correct logout client and active client displayed in logout display with specified ui_locales: #uiLocale"() {
        expect:
        Steps.authenticateWithIdCardInGovssoWithUiLocales(flow, uiLocale)
        Response continueWithExistingSession = Steps.continueWithExistingSession(flow, flow.oidcClientB.clientId, flow.oidcClientB.clientSecret, flow.oidcClientB.fullResponseUrl)
        String idToken = continueWithExistingSession.jsonPath().get("id_token")

        Response initLogoutOidc = Steps.startLogout(flow, idToken, flow.oidcClientB.fullBaseUrl)
        Response initLogoutSession = Steps.followRedirect(flow, initLogoutOidc)

        assertTrue(initLogoutSession.body().htmlPath().getString("/c-tab-login/*}").contains(logoutText), "Correct logged out client")
        assertTrue(initLogoutSession.body().htmlPath().getString("/c-tab-login/*}").contains(sessionText), "Correct active client")

        where:
        uiLocale | logoutText                                    | sessionText
        "et"     | "Olete välja logitud Teenusenimi B teenusest" | "Olete jätkuvalt sisse logitud järgnevatesse teenustesse:Teenusenimi A"
        "en"     | "You have been logged out from Service name B"| "You are still logged in to the following services:Teenusenimi A"
    }

    @Unroll
    @Feature("LOGIN_CONTINUE_SESSION_ENDPOINT")
    def "Correct user data displayed in session continuation display"() {
        expect:
        Steps.authenticateWithIdCardInGovsso(flow)
        Response oidcServiceInitResponse = Steps.startAuthenticationInSsoOidc(flow, flow.oidcClientB.clientId, flow.oidcClientB.fullResponseUrl)
        Response initLoginResponse = Steps.followRedirect(flow, oidcServiceInitResponse)

        assertTrue(initLoginResponse.body().htmlPath().getString("/personal-info/*}").contains("JAAK-KRISTJAN"), "Correct first name")
        assertTrue(initLoginResponse.body().htmlPath().getString("/personal-info/*}").contains("JÕEORG"), "Correct surname")
        assertTrue(initLoginResponse.body().htmlPath().getString("/personal-info/*}").contains("EE38001085718"), "Correct personal code")
        assertTrue(initLoginResponse.body().htmlPath().getString("/personal-info/*}").contains("08.01.1980"), "Correct date of birth")
    }
}