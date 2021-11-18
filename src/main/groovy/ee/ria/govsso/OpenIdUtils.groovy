package ee.ria.govsso

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.*
import com.nimbusds.jwt.SignedJWT
import org.apache.commons.codec.digest.DigestUtils
import org.apache.commons.lang.RandomStringUtils

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
        flow.setNonce("")
        queryParams.put("response_type", "code")
        queryParams.put("scope", "openid")
        queryParams.put("client_id", flow.getOidcClientA().getClientId())
        queryParams.put("redirect_uri", flow.getOidcClientA().fullResponseUrl)
        queryParams.put("state", flow.state)
        //TODO: when nonce includes + its replaced with space in JWT. Encoding is applied, is it ok?
        // queryParams.put("nonce", flow.nonce)
        queryParams.put("ui_locales", "et")
        return queryParams
    }

    static Map<String, String> getAuthorizationParameters(Flow flow, String clientId, String fullResponseUrl) {
        Map<String, String> queryParams = new HashMap<>()
        flow.setState(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setNonce("")
        queryParams.put("response_type", "code")
        queryParams.put("scope", "open_id")
        queryParams.put("client_id", clientId)
        queryParams.put("redirect_uri", fullResponseUrl)
        queryParams.put("state", flow.state)
        //TODO: when nonce includes + its replaced with space in JWT. Encoding is applied, is it ok?
        // queryParams.put("nonce", flow.nonce)
        queryParams.put("ui_locales", "et")
        return queryParams
    }
}
