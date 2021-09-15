<img src="doc/img/eu_regional_development_fund_horizontal.jpg" width="350" height="200">

# GOVSSO integration tests

Tests for GOVSSO (both Hydra OIDC and Estonian specific session service component)

## Prerequisites

1. SUT (GOVSSO) must be deployed as accessible service
   
2. Fetch the tests:

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

| Parameter | Default |  Description |
|------------|--------------|------------|
| oidcservice.protocol | https | Service protocol. |
| oidcservice.host | oidc-service | Service URL. |
| oidcservice.port | 8443 | Service port. |


## Execute tests and generate report

1. To run the tests:
   
`./mvn clean test`

2. To check the results:

a) Surefire plugin generates reports in ../target/surefire-reports folder.

b) For a comprehensive report, Allure is required ([instructions for download.](https://docs.qameta.io/allure/#_installing_a_commandline)). To generate the report execute:

`allure serve .../govsso-test/allure-results/`

## To see Allure report after running tests in IntelliJ 

Configure correct Allure results directory in IntelliJ in order to view Allure report when running tests from IntelliJ

`Run-> Edit configurations-> Templates-> JUnit-> VM Options: -ea -Dallure.results.directory=$ProjectFileDir$/target/allure-results`

And delete all existing run configurations