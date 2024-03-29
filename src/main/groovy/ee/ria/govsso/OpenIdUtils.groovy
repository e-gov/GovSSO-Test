package ee.ria.govsso

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.*
import com.nimbusds.jwt.SignedJWT
import org.apache.commons.codec.digest.DigestUtils
import org.apache.commons.lang3.RandomStringUtils

import java.text.ParseException

import static org.hamcrest.Matchers.is
import static org.hamcrest.MatcherAssert.assertThat

class OpenIdUtils {


    static Boolean isTokenSignatureValid(JWKSet jwkSet, SignedJWT signedJWT) throws JOSEException {
        List<JWK> matches = new JWKSelector(new JWKMatcher.Builder()
                .keyType(KeyType.RSA)
                .build())
                .select(jwkSet)

        RSAKey rsaKey = (RSAKey) matches.get(0)
        JWSVerifier verifier = new RSASSAVerifier(rsaKey)
        return signedJWT.verify(verifier)
    }

    static Map getAuthorizationParametersWithDefaults(Flow flow) {
        flow.setState(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setNonce(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setClientId(flow.oidcClientA.clientId)
        Map queryParams = [response_type: "code",
                           scope        : "openid",
                           client_id    : flow.oidcClientA.clientId,
                           redirect_uri : flow.oidcClientA.fullResponseUrl,
                           state        : flow.state,
                           nonce        : flow.nonce,
                           prompt       : "consent",
                           ui_locales   : "et",
                           acr_values   : "high"]
        return queryParams
    }

    static Map getAuthorizationParameters(Flow flow, String clientId, String fullResponseUrl) {
        flow.setState(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setNonce(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setClientId(clientId)
        Map queryParams = [response_type: "code",
                           scope        : "openid",
                           client_id    : clientId,
                           redirect_uri : fullResponseUrl,
                           state        : flow.state,
                           nonce        : flow.nonce,
                           prompt       : "consent",
                           acr_values   : "high"]
        return queryParams
    }

    static Map getAuthorizationParametersWithScope(Flow flow, String clientId, String fullResponseUrl, String scope) {
        flow.setState(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setNonce(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setClientId(clientId)
        Map queryParams = [response_type: "code",
                           scope        : scope,
                           client_id    : clientId,
                           redirect_uri : fullResponseUrl,
                           state        : flow.state,
                           nonce        : flow.nonce,
                           prompt       : "consent",
                           ui_locales   : "et",
                           acr_values   : "high"]
        return queryParams
    }

    static Map getSessionUpdateParametersWithDefaults(Flow flow, String idTokenHint) {
        flow.setState(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setNonce(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        Map queryParams = [response_type: "code",
                           scope        : "openid",
                           client_id    : flow.oidcClientA.clientId,
                           redirect_uri : flow.oidcClientA.fullResponseUrl,
                           state        : flow.state,
                           nonce        : flow.nonce,
                           prompt       : "none",
                           id_token_hint: idTokenHint]
        return queryParams
    }

    static SignedJWT verifyTokenAndReturnSignedJwtObject(Flow flow, String token) throws ParseException, JOSEException, IOException {
        SignedJWT signedJWT = SignedJWT.parse(token)
        assertThat("Token Signature is not valid!", isTokenSignatureValid(flow.jwkSet, signedJWT), is(true))
        return signedJWT
    }
}
