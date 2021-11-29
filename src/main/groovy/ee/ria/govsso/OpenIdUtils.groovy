package ee.ria.govsso

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.*
import com.nimbusds.jwt.SignedJWT
import org.apache.commons.codec.digest.DigestUtils
import org.apache.commons.lang.RandomStringUtils
import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers

import java.text.ParseException

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

    static SignedJWT verifyTokenAndReturnSignedJwtObject(Flow flow, String token) throws ParseException, JOSEException, IOException {
        SignedJWT signedJWT = SignedJWT.parse(token)
        MatcherAssert.assertThat("Token Signature is not valid!", isTokenSignatureValid(flow.jwkSet, signedJWT), CoreMatchers.is(true))
        MatcherAssert.assertThat(signedJWT.getJWTClaimsSet().getAudience().get(0), Matchers.equalTo(flow.oidcClientA.clientId))
        MatcherAssert.assertThat(signedJWT.getJWTClaimsSet().getIssuer(), Matchers.equalTo(flow.openIdServiceConfiguration.get("issuer")))
        Date date = new Date()
        MatcherAssert.assertThat("Expected current: " + date + " to be before exp: " + signedJWT.getJWTClaimsSet().getExpirationTime(), date.before(signedJWT.getJWTClaimsSet().getExpirationTime()), CoreMatchers.is(true))
//TODO: nbf not used in govsso?
//        assertThat("Expected current: " + date + " to be after nbf: " + signedJWT.getJWTClaimsSet().getNotBeforeTime(), date.after(signedJWT.getJWTClaimsSet().getNotBeforeTime()), is(true))
        if (!flow.getNonce().isEmpty()) {
            MatcherAssert.assertThat(signedJWT.getJWTClaimsSet().getStringClaim("nonce"), Matchers.equalTo(flow.getNonce()))
        }
//TODO: state is not propagated to JWT in govsso?
//        assertThat(signedJWT.getJWTClaimsSet().getStringClaim("state"), equalTo(flow.getState()))
        return signedJWT
    }
}
