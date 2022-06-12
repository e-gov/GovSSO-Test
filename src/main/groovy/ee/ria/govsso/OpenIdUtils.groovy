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
        queryParams.put("ui_locales", "et")
        queryParams.put("acr_values", "high")
        flow.setClientId(clientId)
        return queryParams
    }

    static Map<String, String> getSessionRefreshParametersWithDefaults(Flow flow, String idTokenHint) {
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

    static Map<String, String> getSessionRefreshParametersWithScope(Flow flow, String idTokenHint, String scope) {
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

    static Map<String, String> getSessionRefreshParameters(Flow flow, String idTokenHint, String clientId, String fullResponseUrl) {
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

    static SignedJWT verifyTokenAndReturnSignedJwtObjectWithDefaults(Flow flow, String token) throws ParseException, JOSEException, IOException {
        SignedJWT signedJWT = SignedJWT.parse(token)
        MatcherAssert.assertThat("Token Signature is not valid!", isTokenSignatureValid(flow.jwkSet, signedJWT), CoreMatchers.is(true))
        MatcherAssert.assertThat(signedJWT.getJWTClaimsSet().getAudience().get(0), Matchers.equalTo(flow.oidcClientA.clientId))
        MatcherAssert.assertThat(signedJWT.getJWTClaimsSet().getIssuer(), Matchers.equalTo(flow.openIdServiceConfiguration.get("issuer")))
        Date date = new Date()
        MatcherAssert.assertThat("Expected current: " + date + " to be before exp: " + signedJWT.getJWTClaimsSet().getExpirationTime(), date.before(signedJWT.getJWTClaimsSet().getExpirationTime()), CoreMatchers.is(true))
        //TODO: nbf implemented later
//        assertThat("Expected current: " + date + " to be after nbf: " + signedJWT.getJWTClaimsSet().getNotBeforeTime(), date.after(signedJWT.getJWTClaimsSet().getNotBeforeTime()), is(true))
        if (!flow.getNonce().isEmpty()) {
            MatcherAssert.assertThat(signedJWT.getJWTClaimsSet().getStringClaim("nonce"), Matchers.equalTo(flow.getNonce()))
        }
        return signedJWT
    }

    static SignedJWT verifyTokenAndReturnSignedJwtObject(Flow flow, String token, String clientId) throws ParseException, JOSEException, IOException {
        SignedJWT signedJWT = SignedJWT.parse(token)
        MatcherAssert.assertThat("Token Signature is not valid!", isTokenSignatureValid(flow.jwkSet, signedJWT), CoreMatchers.is(true))
        MatcherAssert.assertThat(signedJWT.getJWTClaimsSet().getAudience().get(0), Matchers.equalTo(clientId))
        MatcherAssert.assertThat(signedJWT.getJWTClaimsSet().getIssuer(), Matchers.equalTo(flow.openIdServiceConfiguration.get("issuer")))
        Date date = new Date()
        MatcherAssert.assertThat("Expected current: " + date + " to be before exp: " + signedJWT.getJWTClaimsSet().getExpirationTime(), date.before(signedJWT.getJWTClaimsSet().getExpirationTime()), CoreMatchers.is(true))
        //TODO: nbf implemented later
//        assertThat("Expected current: " + date + " to be after nbf: " + signedJWT.getJWTClaimsSet().getNotBeforeTime(), date.after(signedJWT.getJWTClaimsSet().getNotBeforeTime()), is(true))
        if (!flow.getNonce().isEmpty()) {
            MatcherAssert.assertThat(signedJWT.getJWTClaimsSet().getStringClaim("nonce"), Matchers.equalTo(flow.getNonce()))
        }
        return signedJWT
    }
}
