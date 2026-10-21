package ee.ria.govsso.configuration

interface SessionServiceConf extends NodeServiceConf {
    String initUrl()

    String logoutInitUrl()

    String continueSessionUrl()

    String reauthenticateUrl()

    String logoutContinueSessionUrl()

    String logoutEndSessionUrl()

    String loginRejectUrl()

    String consentUrl()

    String consentConfirmUrl()

    String taraCallbackUrl()

    String sessionsUrl()
}
