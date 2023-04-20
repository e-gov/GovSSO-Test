package ee.ria.govsso.database

import ee.ria.govsso.Flow
import groovy.sql.Sql

class DatabaseConnection {

    static Sql getSql(Flow flow) {
        String url = flow.ssoOidcDatabase.fullSsoOidcDatabaseUrl
        String username = flow.ssoOidcDatabase.username
        String password = flow.ssoOidcDatabase.password
        String driver = "org.postgresql.Driver"
        return Sql.newInstance(url, username, password, driver)
    }
}