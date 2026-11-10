package ee.ria.govsso.database

import groovy.sql.Sql

import java.time.Duration

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.greaterThan

class SqlQueries {

    static expireSession(Sql sql, String sessionId) {
        sql.execute "UPDATE public.hydra_oauth2_authentication_session SET max_age = max_age - INTERVAL '15 minutes 1 second' WHERE id=?", [sessionId]
    }

    // For consent expiration, requested_at is changed instead of remember_for due to test optimisation. Changing either value results in the same outcome.
    static expireConsent(Sql sql, String consentChallenge) {
        sql.execute "UPDATE public.hydra_oauth2_flow SET requested_at = requested_at - INTERVAL '15 minutes 1 second' WHERE consent_challenge_id=?", [consentChallenge]
    }

    // Moves the authentication time backwards, so that checks measuring the age of a session do not have to wait it out.
    static ageLoginAuthentication(Sql sql, String sessionId, Duration age) {
        sql.execute "UPDATE public.hydra_oauth2_authentication_session SET authenticated_at = authenticated_at - ? * INTERVAL '1 second' WHERE id=?", [age.toSeconds(), sessionId]
        sql.execute "UPDATE public.hydra_oauth2_flow SET login_authenticated_at = login_authenticated_at - ? * INTERVAL '1 second' WHERE login_session_id=?", [age.toSeconds(), sessionId]
    }

    // Moves the TARA authentication time in the session context backwards. GovSSO measures the session max duration from it.
    static ageTaraAuthentication(Sql sql, String sessionId, Duration age) {
        ageUserAttributeTime(sql, sessionId, "tara_auth_time", age)
    }

    // Moves the auth handover time in the session context backwards. GovSSO measures the max duration of a handed over session from it.
    static ageAuthHandover(Sql sql, String sessionId, Duration age) {
        ageUserAttributeTime(sql, sessionId, "auth_handover_time", age)
    }

    private static void ageUserAttributeTime(Sql sql, String sessionId, String attribute, Duration age) {
        int updatedRows = sql.executeUpdate "UPDATE public.hydra_oauth2_flow SET context = jsonb_set(context, ARRAY['user_attributes', CAST(? AS text)], to_jsonb((context #>> ARRAY['user_attributes', CAST(? AS text)])::bigint - ?)) WHERE login_session_id=? AND context #> ARRAY['user_attributes', CAST(? AS text)] IS NOT NULL", [attribute, attribute, age.toSeconds(), sessionId, attribute]
        assertThat("Session context contains the user attribute " + attribute, updatedRows, greaterThan(0))
    }

    static inactivateRefreshToken(Sql sql, String consentChallenge) {
        sql.execute "UPDATE public.hydra_oauth2_refresh SET active = FALSE WHERE challenge_id=?", [consentChallenge]
    }

    static getConsentRememberFor(Sql sql, String consentChallenge) {
        Object response = sql.firstRow("SELECT consent_remember_for FROM public.hydra_oauth2_flow WHERE consent_challenge_id=?", [consentChallenge])
        Integer consentRememberFor = response.consent_remember_for as Integer
        return consentRememberFor
    }

    // For cleanup of the open flows for test user
    static deleteFlowsForSubject(Sql sql, String subject) {
        sql.execute "DELETE FROM public.hydra_oauth2_flow WHERE subject=?", [subject]
    }
}
