package ee.ria.govsso.database

import groovy.sql.Sql

class SqlQueries {

    static expireSession(Sql sql, String sessionId) {
        sql.execute "UPDATE public.hydra_oauth2_authentication_session SET max_age = max_age - INTERVAL '15 minutes 1 second' WHERE id=?", [sessionId]
    }

    // For consent expiration, requested_at is changed instead of remember_for due to test optimisation. Changing either value results in the same outcome.
    static expireConsent(Sql sql, String consentChallenge) {
        sql.execute "UPDATE public.hydra_oauth2_consent_request_handled SET requested_at = requested_at - INTERVAL '15 minutes 1 second' WHERE challenge=?", [consentChallenge]
    }

    static inactivateRefreshToken(Sql sql, String consentChallenge) {
        sql.execute "UPDATE public.hydra_oauth2_refresh SET active = FALSE WHERE challenge_id=?", [consentChallenge]
    }
}
