<img src="doc/img/eu_regional_development_fund_horizontal.jpg" width="350" height="200">

# GovSSO integration tests

Tests for GovSSO (both Ory Hydra OIDC and Estonian specific session service component)

## Prerequisites

* Java 11 JDK

1. SUT (GovSSO) must be deployed as accessible service

2. Some tests require deployment of TARA2

3. Fetch the tests:

`git clone https://github.com/e-gov/GovSSO-Test`

## Configuring the test

1. Configure the properties file. application.properties file needs to be either in `src/test/resources` directory or
   its location configured with .env file `src/test/resources`. Example of .env file:

```
configuration_base_path=/home/me/IdeaProjects/govsso-configuration
configuration_path=dev-local
```   

The example application.properties file with values are given ../src/test/resource/sample_application.properties

Description of values:

**ssooidcservice** - Hydra OIDC service parameters

**sessionservice** - Estonian specific session service parameters.

**ssooidcclienta** - Tests act like connecting OIDC client. This client must be registered in GovSSO service.

**ssooidcclientb** - Tests act like connecting OIDC client. This client must be registered in GovSSO service.

**ca-proxyservice** - Foreign country (CA) proxy service configuration for eIDAS authentication tests.

**idp** - Foreign country (CA) identity provider configuration for eIDAS authentication tests.

**taraservice** - login service configuration used for connecting to the authentication service

| Parameter                               | Default                                           | Description                                            |
|-----------------------------------------|---------------------------------------------------|--------------------------------------------------------|
| ssooidcservice.protocol                 | http                                              | Service protocol.                                      |
| ssooidcservice.host                     | oidc-service                                      | Service URL.                                           |
| ssooidcservice.port                     | 13444                                             | Service port.                                          |
| ssooidcservice.revocation               | /oauth2/revoke                                    | Session revocation endpoint.                           |
| ssooidcservice.logout                   | /oauth2/sessions/logout                           | Session logout endpoint.                               |
| ssooidcservice.authenticationRequestUrl | /oauth2/auth                                      | OIDC flow start endpoint.                              |
| ssooidcservice.configurationUrl         | /.well-known/openid-configuration                 | OIDC metadata endpoint.                                |
| ssooidcservice.jwksUrl                  | /.well-known/jwks.json                            | Signing key info endpoint.                             |
| ssooidcdatabase.protocol                | jdbc                                              | Database protocol.                                     |
| ssooidcdatabase.host                    | oidc-db                                           | Database URL.                                          |
| ssooidcdatabase.port                    | 5432                                              | Database port.                                         |
| ssooidcdatabase.databaseUrl             | /oidc-db                                          | Database endpoint.                                     |
| ssooidcdatabase.username                | username                                          | Database users' username                               |
| ssooidcdatabase.password                | password                                          | Database users' password                               |
| sessionservice.protocol                 | http                                              | Service protocol.                                      |
| sessionservice.host                     | session-service                                   | Service URL.                                           |
| sessionservice.port                     | 14080                                             | Service port.                                          |
| sessionservice.node.protocol            | http                                              | Service node protocol. Used in monitoring tests.       |
| sessionservice.node.host                | session-service                                   | Service node URL. Used in monitoring tests.            |
| sessionservice.node.port                | 14080                                             | Service node port. Used in monitoring tests.           |
| sessionservice.initUrl                  | /login/init                                       | Service authentication start endpoint.                 |
| sessionservice.continueSessionUrl       | /login/continuesession                            | Service session continuation endpoint.                 |
| sessionservice.reauthenticateUrl        | /login/reauthenticate                             | Service reauthentication endpoint.                     |
| sessionservice.taraCallbackUrl          | /login/taracallback                               | Service authentication redirect endpoint.              |
| sessionservice.loginRejectUrl           | /login/reject                                     | Service cancel authentication endpoint.                |
| sessionservice.logoutInitUrl            | /logout/init                                      | Service logout start endpoint.                         |
| sessionservice.logoutContinueSessionUrl | /logout/continuesession                           | Service logout with continuation endpoint.             |
| sessionservice.logoutEndSessionUrl      | /logout/endsession                                | Service logout with end all sessions endpoint.         |
| sessionservice.consentUrl               | /consent/init                                     | Service consent selection endpoint.                    |
| sessionservice.consentConfirmUrl        | /auth/consent/confirm                             | Service consent confirmation endpoint.                 |
| sessionservice.healthUrl                | /actuator/health                                  | Service health endpoint.                               |
| sessionservice.readinessUrl             | /actuator/health/readiness                        | Service readiness endpoint.                            |
| sessionservice.livenessUrl              | /actuator/health/liveness                         | Service liveness endpoint.                             |
| sessionservice.infoUrl                  | /actuator/info                                    | Service info endpoint.                                 |
| sessionservice.sessions                 | /admin/sessions                                   | Service sessions endpoint.                             |
| taraservice.protocol                    | https                                             | Service protocol.                                      |
| taraservice.host                        | login-service-backend                             | Service URL.                                           |
| taraservice.initUrl                     | https                                             | Authentication start endpoint in login service.        |
| taraservice.midInitUrl                  | /auth/mid/init                                    | Mobile-ID start endpoint.                              |
| taraservice.midPollUrl                  | /auth/mid/poll                                    | Mobile-ID status polling endpoint.                     |
| taraservice.webEidInitUrl               | /auth/id/init                                     | ID-card authentication start endpoint.                 |
| taraservice.webEidLoginUrl              | /auth/id/login                                    | ID-card authentication authToken submit endpoint.      |
| taraservice.sidInitUrl                  | /auth/sid/init                                    | Smart-ID start endpoint.                               |
| taraservice.sidPollUrl                  | /auth/sid/poll                                    | Smart-ID status polling endpoint.                      |
| taraservice.authAcceptUrl               | /auth/accept                                      | Authentication accept endpoint.                        |
| taraservice.authRejectUrl               | /auth/reject                                      | Authentication reject endpoint.                        |
| taraservice.eidasInitUrl                | /auth/eidas/init                                  | eIDAS authentication start endpoint.                   |
| taraservice.eidasCallbackUrl            | /auth/eidas/callback                              | eIDAS authentication return endpoint.                  |
| taraservice.authLegalInitUrl            | /auth/legalperson/init                            | Legal person authentication start endpoint.            |
| taraservice.authLegalPersonUrl          | /auth/legalperson                                 | Legal person selection endpoint.                       |
| taraservice.authLegalConfirmUrl         | /auth/legalperson/confirm                         | Legal person confirmation endpoint.                    |
| taraservice.consentUrl                  | /auth/consent                                     | Authentication consent selection endpoint.             |
| taraservice.consentConfirmUrl           | /auth/consent/confirm                             | Authentication consent confirmation endpoint.          |
| ca-proxyservice.protocol                | https                                             | Service protocol.                                      |
| ca-proxyservice.host                    | eidas-caproxy                                     | Service URL.                                           |
| ca-proxyservice.port                    | 8080                                              | Service port.                                          |
| ca-proxyservice.consentUrl              | /SpecificProxyService/AfterCitizenConsentResponse | Authentication consent endpoint.                       |
| idp.protocol                            | https                                             | Service protocol.                                      |
| idp.host                                | eidas-caproxy                                     | Service URL.                                           |
| idp.port                                | 8081                                              | Service port.                                          |
| idp.responseUrl                         | /IdP/Response                                     | Authentication response endpoint.                      |
| ssooidcclienta.protocol                 | https                                             | GovSSO mock client A protocol.                         |
| ssooidcclienta.host                     | sso-client-a                                      | GovSSO mock client A host.                             |
| ssooidcclienta.port                     | 11443                                             | GovSSO mock client A port.                             |
| ssooidcclienta.responseUrl              | /oauth/response                                   | GovSSO mock client A authentication response endpoint. |
| ssooidcclienta.logoutRedirectUrl        | /logout/url                                       | GovSSO mock client A logout redirect endpoint.         |
| ssooidcclienta.clientId                 | client-a                                          | GovSSO mock client A ID.                               |
| ssooidcclienta.secret                   | secreta                                           | GovSSO mock client A secret.                           |
| ssooidcclienta.expiredJwt               | eyJhbG...                                         | GovSSO mock client A expired ID token.                 |
| ssooidcclientb.protocol                 | https                                             | GovSSO mock client B protocol.                         |
| ssooidcclientb.host                     | sso-client-b                                      | GovSSO mock client B host.                             |
| ssooidcclientb.port                     | 12443                                             | GovSSO mock client B port.                             |
| ssooidcclientb.responseUrl              | /oauth/response                                   | GovSSO mock client B authentication response endpoint. |
| ssooidcclientb.logoutRedirectUrl        | /logout/url                                       | GovSSO mock client B logout redirect endpoint.         |
| ssooidcclientb.clientId                 | client-b                                          | GovSSO mock client B ID.                               |
| ssooidcclientb.secret                   | secretb                                           | GovSSO mock client B secret.                           |

## Execute tests and generate report

1. To run the tests:

`./mvnw clean test`

2. To check the results:

a) Surefire plugin generates reports in ../target/surefire-reports folder.

b) For a comprehensive report, Allure is
required ([instructions for download.](https://docs.qameta.io/allure/#_installing_a_commandline)). To generate the
report execute:

`allure serve .../GovSSO-Test/allure-results/`

## To see Allure report after running tests in IntelliJ

Configure correct Allure results directory in IntelliJ in order to view Allure report when running tests from IntelliJ

`Run-> Edit configurations-> Templates-> JUnit-> VM Options: -ea -Dallure.results.directory=$ProjectFileDir$/target/allure-results`

And delete all existing run configurations
