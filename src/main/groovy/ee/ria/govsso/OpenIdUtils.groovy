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

    static Map<String, String> getAuthorizationParametersWithDefaults(Flow flow) {
        Map<String, String> queryParams = new HashMap<>()
        flow.setState(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setNonce(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        queryParams.put("response_type", "code")
        queryParams.put("scope", "openid")
        queryParams.put("client_id", flow.getOidcClientA().getClientId())
        queryParams.put("redirect_uri", flow.getOidcClientA().fullResponseUrl)
        queryParams.put("state", flow.state)
        queryParams.put("nonce", flow.nonce)
        queryParams.put("prompt", "consent")
        queryParams.put("ui_locales", "et")
        queryParams.put("acr_values", "high")
        flow.setClientId(flow.getOidcClientA().getClientId())
        return queryParams
    }

    static Map<String, String> getAuthorizationParameters(Flow flow, String clientId, String fullResponseUrl) {
        Map<String, String> queryParams = new HashMap<>()
        flow.setState(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setNonce(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        queryParams.put("response_type", "code")
        queryParams.put("scope", "openid")
        queryParams.put("client_id", clientId)
        queryParams.put("redirect_uri", fullResponseUrl)
        queryParams.put("state", flow.state)
        queryParams.put("nonce", flow.nonce)
        queryParams.put("prompt", "consent")
        queryParams.put("acr_values", "high")
        flow.setClientId(clientId)
        return queryParams
    }

    static Map<String, String> getAuthorizationParametersWithScope(Flow flow, String clientId, String fullResponseUrl, String scope) {
        Map<String, String> queryParams = new HashMap<>()
        flow.setState(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setNonce(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        queryParams.put("response_type", "code")
        queryParams.put("scope", scope)
        queryParams.put("client_id", clientId)
        queryParams.put("redirect_uri", fullResponseUrl)
        queryParams.put("state", flow.state)
        queryParams.put("nonce", flow.nonce)
        queryParams.put("prompt", "consent")
        queryParams.put("ui_locales", "et")
        queryParams.put("acr_values", "high")
        flow.setClientId(clientId)
        return queryParams
    }

    static Map<String, String> getSessionUpdateParametersWithDefaults(Flow flow, String idTokenHint) {
        Map<String, String> queryParams = new HashMap<>()
        flow.setState(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setNonce(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        queryParams.put("response_type", "code")
        queryParams.put("scope", "openid")
        queryParams.put("client_id", flow.getOidcClientA().getClientId())
        queryParams.put("redirect_uri", flow.getOidcClientA().fullResponseUrl)
        queryParams.put("state", flow.state)
        queryParams.put("nonce", flow.nonce)
        queryParams.put("prompt", "none")
        queryParams.put("id_token_hint", idTokenHint)
        flow.setClientId(flow.getOidcClientA().getClientId())
        return queryParams
    }

    static Map<String, String> getSessionUpdateParametersWithScope(Flow flow, String idTokenHint, String scope) {
        Map<String, String> queryParams = new HashMap<>()
        flow.setState(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setNonce(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        queryParams.put("response_type", "code")
        queryParams.put("scope", scope)
        queryParams.put("client_id", flow.getOidcClientA().getClientId())
        queryParams.put("redirect_uri", flow.getOidcClientA().fullResponseUrl)
        queryParams.put("state", flow.state)
        queryParams.put("nonce", flow.nonce)
        queryParams.put("prompt", "none")
        queryParams.put("id_token_hint", idTokenHint)
        flow.setClientId(flow.getOidcClientA().getClientId())
        return queryParams
    }

    static Map<String, String> getSessionUpdateParameters(Flow flow, String idTokenHint, String clientId, String fullResponseUrl) {
        Map<String, String> queryParams = new HashMap<>()
        flow.setState(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setNonce(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        queryParams.put("response_type", "code")
        queryParams.put("scope", "openid")
        queryParams.put("client_id", clientId)
        queryParams.put("redirect_uri", fullResponseUrl)
        queryParams.put("state", flow.state)
        queryParams.put("nonce", flow.nonce)
        queryParams.put("prompt", "none")
        queryParams.put("id_token_hint", idTokenHint)
        flow.setClientId(clientId)
        return queryParams
    }

    static SignedJWT verifyTokenAndReturnSignedJwtObject(Flow flow, String token) throws ParseException, JOSEException, IOException {
        SignedJWT signedJWT = SignedJWT.parse(token)
        assertThat("Token Signature is not valid!", isTokenSignatureValid(flow.jwkSet, signedJWT), is(true))
        return signedJWT
    }
}
