<img src="doc/img/eu_regional_development_fund_horizontal.jpg" width="350" height="200">

# GOVSSO integration tests

Tests for GOVSSO (both Hydra OIDC and Estonian specific session service component)

## Prerequisites

1. SUT (GOVSSO) must be deployed as accessible service

2. Some tests require deployment of TARA2
   
3. Fetch the tests:

`git clone https://github.com/e-gov/GOVSSO-Test`

## Configuring the test

1. Configure the properties file. 
   application.properties file needs to be either in `src/test/resources` directory or its location configured with .env file `src/test/resources`.
   Example of .env file:
   
```
configuration_base_path=/home/me/IdeaProjects/govsso-configuration
configuration_path=dev-local
```   

The example application.properties file with values are given ../src/test/resource/sample_application.properties

Description of values:

**ssooidcservice** - Hydra OIDC service parameters

**sessionservice** - Estonian specific session service parameters.

**ssooidcclienta** - Tests act like connecting OIDC client. This client must be registered in GOVSSO service.

**ssooidcclientb** - Tests act like connecting OIDC client. This client must be registered in GOVSSO service.

**ca-proxyservice** - Foreign country (CA) proxy service configuration for eIDAS authentication tests.

**idp** - Foreign country (CA) identity provider configuration for eIDAS authentication tests.

**taraservice** - login service configuration for specific node, used for connecting to the authentication service

| Parameter | Default |  Description |
|------------|--------------|------------|
| ssooidcservice.protocol | http | Service protocol. |
| ssooidcservice.host | oidc-service | Service URL. |
| ssooidcservice.port | 13444 | Service port. |
| ssooidcservice.revocation | /oauth2/revoke  | Session revocation endpoint. |
| ssooidcservice.logout | /oauth2/sessions/logout  | Session logout endpoint. |
| ssooidcservice.authenticationRequestUrl | /oauth2/auth  | OIDC flow start endpoint. |
| ssooidcservice.configurationUrl | /.well-known/openid-configuration  | OIDC metadata endpoint. |
| ssooidcservice.jwksUrl | /.well-known/jwks.json  | Signing key info endpoint. |
| sessionservice.protocol | http | Service protocol. |
| sessionservice.host | session-service | Service URL. |
| sessionservice.port | 14080 | Service port. |
| sessionservice.initUrl | /auth/init | Service authentication start endpoint. |
| sessionservice.consentUrl | /auth/consent | Service consent selection endpoint. |
| sessionservice.consentConfirmUrl | /auth/consent/confirm | Service consent confirmation endpoint. |
| sessionservice.taraCallbackUrl | /auth/taracallback | Service authentication redirect endpoint. |
| sessionservice.healthUrl | /actuator/health | Service health endpoint. |
| sessionservice.readinessUrl | /actuator/health/readiness | Service readiness endpoint. |
| sessionservice.infoUrl | /actuator/info | Service info endpoint. |
| taraservice.protocol | https | Service protocol. |
| taraservice.host | login-service-backend | Service URL. |
| taraservice.port | 8444 | Service port. |
| taraservice.initUrl | https | Authentication start endpoint in login service. |
| taraservice.midInitUrl | /auth/mid/init | Mobile-ID start endpoint. |
| taraservice.midPollUrl | /auth/mid/poll | Mobile-ID status polling endpoint. |
| taraservice.idCardInitUrl | /auth/id | ID-card authentication endpoint.. |
| taraservice.sidInitUrl | /auth/sid/init | Smart-ID start endpoint. |
| taraservice.sidPollUrl | /auth/sid/poll | Smart-ID status polling endpoint. |
| taraservice.authAcceptUrl | /auth/accept | Authentication accept endpoint. |
| taraservice.authRejectUrl | /auth/reject | Authentication reject endpoint. |
| taraservice.eidasInitUrl | /auth/eidas/init | eIDAS authentication start endpoint. |
| taraservice.eidasCallbackUrl | /auth/eidas/callback | eIDAS authentication return endpoint. |
| taraservice.authLegalInitUrl | /auth/legalperson/init | Legal person authentication start endpoint. |
| taraservice.authLegalPersonUrl | /auth/legalperson | Legal person selection endpoint. |
| taraservice.authLegalConfirmUrl | /auth/legalperson/confirm | Legal person confirmation endpoint. |
| taraservice.consentUrl | /auth/consent | Authentication consent selection endpoint. |
| taraservice.consentConfirmUrl | /auth/consent/confirm | Authentication consent confirmation endpoint. |
| ca-proxyservice.protocol | https | Service protocol. |
| ca-proxyservice.host | eidas-caproxy | Service URL. |
| ca-proxyservice.port | 8080 | Service port. |
| ca-proxyservice.consentUrl | /SpecificProxyService/AfterCitizenConsentResponse | Authentication consent endpoint. |
| idp.protocol | https | Service protocol. |
| idp.host | eidas-caproxy | Service URL. |
| idp.port | 8081 | Service port. |
| idp.responseUrl | /IdP/Response | Authentication response endpoint. |
| ee-connector.protocol | https | Service protocol. |
| ee-connector.host | eidas-specificconnector | Service URL. |
| ee-connector.port | 8443 | Service port. |
| ee-connector.authenticationRequestUrl | /SpecificConnector/ServiceProvider | Estonian eIDAS connector authentication start endpoint. |
| ssooidcclienta.protocol | https | GOVSSO mock client A protocol. |
| ssooidcclienta.host | sso-client-a | GOVSSO mock client A host. |
| ssooidcclienta.port | 11443 | GOVSSO mock client A port. |
| ssooidcclienta.responseUrl | /oauth/response | GOVSSO mock client A authentication response endpoint. |
| ssooidcclienta.clientId | client-a | GOVSSO mock client A ID. |
| ssooidcclienta.secret | secreta | GOVSSO mock client A secret. |
| ssooidcclientb.protocol | https | GOVSSO mock client B protocol. |
| ssooidcclientb.host | sso-client-b | GOVSSO mock client B host. |
| ssooidcclientb.port | 12443 | GOVSSO mock client B port. |
| ssooidcclientb.responseUrl | /oauth/response | GOVSSO mock client B authentication response endpoint. |
| ssooidcclientb.clientId | client-b | GOVSSO mock client B ID. |
| ssooidcclientb.secret | secretb | GOVSSO mock client B secret. |


## Execute tests and generate report

1. To run the tests:
   
`./mvn clean test`

2. To check the results:

a) Surefire plugin generates reports in ../target/surefire-reports folder.

b) For a comprehensive report, Allure is required ([instructions for download.](https://docs.qameta.io/allure/#_installing_a_commandline)). To generate the report execute:

`allure serve .../GOVSSO-test/allure-results/`

## To see Allure report after running tests in IntelliJ 

Configure correct Allure results directory in IntelliJ in order to view Allure report when running tests from IntelliJ

`Run-> Edit configurations-> Templates-> JUnit-> VM Options: -ea -Dallure.results.directory=$ProjectFileDir$/target/allure-results`

And delete all existing run configurations