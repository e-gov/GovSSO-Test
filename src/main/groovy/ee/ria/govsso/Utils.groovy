package ee.ria.govsso

import com.fasterxml.jackson.databind.ObjectMapper
import io.qameta.allure.Allure
import org.apache.commons.lang3.StringUtils
import org.json.JSONObject
import org.spockframework.lang.Wildcard
import io.restassured.response.Response

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.Certificate
import java.time.Duration
import java.util.regex.Matcher
import java.util.regex.Pattern

class Utils {

    private static final Pattern DURATION_PATTERN = ~/^(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/

    static Map setParameter(Map hashMap, Object param, Object paramValue) {
        if (!(param instanceof Wildcard)) {
            if (!(paramValue instanceof Wildcard)) {
                hashMap.put(param, paramValue)
            } else {
                hashMap.put(param, "")
            }
        }
        return hashMap
    }

    static String getParamValueFromResponseHeader(Response response, String paramName) {
        String[] parameters = response.getHeader("location").toURL().getQuery().split("&")
        String paramValue = null
        parameters.each {
            if (it.split("=")[0] == paramName) {
                paramValue = it.split("=")[1]
            }
        }
        if (paramValue != null) {
            return URLDecoder.decode(paramValue, "UTF-8")
        } else {
            return null
        }
    }

    static String getFileAsString(String filename) {
        return new File(filename).readLines().join()
    }

    static void storeTaraServiceUrlToflow(Flow flow, String url) {
        URL rawUrl = new URI(url).toURL()
        flow.taraService.taraloginBaseUrl = rawUrl.getProtocol() + "://" + rawUrl.getHost() + getPortIfPresent(rawUrl)
    }

    static String getPortIfPresent(URL url) {
        String port = ""
        if (url.getPort() != -1) {
            port = ":" + url.getPort()
        }
        return port
    }

    static void addJsonAttachment(String name, String json) throws IOException {
        ObjectMapper mapper = new ObjectMapper()
        Object jsonObject = mapper.readValue(json, Object.class)
        String prettyJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject)
        Allure.addAttachment(name, "application/json", prettyJson, "json")
    }

    static JSONObject getWebEidAuthTokenParameters(Flow flow, String signature) {
        JSONObject formParams = ["authToken": ["algorithm"            : "ES384",
                                               "appVersion"           : "https://web-eid.eu/web-eid-app/releases/2.0.2+566",
                                               "format"               : "web-eid:1.0",
                                               "signature"            : signature,
                                               "unverifiedCertificate": flow.authCertificate]]
        return formParams
    }

    static signAuthenticationValue(Flow flow, String origin, String challenge) {
        //Read keystore and keys
        KeyStore store = KeyStore.getInstance("PKCS12")
        char[] password = "1234".toCharArray()
        store.load(new FileInputStream("src/test/resources/joeorg_auth_EC.p12"), password)
        Certificate certificate = store.getCertificate("1")
        PrivateKey privateKey = (PrivateKey) store.getKey("1", password)

        //Set authentication certificate to flow for authToken unverifiedCertificate value
        flow.setAuthCertificate(Base64.getEncoder().encodeToString(certificate.getEncoded()))

        //Hash origin & challenge nonce
        MessageDigest md = MessageDigest.getInstance("SHA-384")
        byte[] originDigest = md.digest(origin.getBytes())
        byte[] challengeDigest = md.digest(challenge.getBytes())

        //Combine origin and challenge nonce hashes to create authentication value to be signed
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream()
        outputStream.write(originDigest)
        outputStream.write(challengeDigest)

        byte[] authValue = outputStream.toByteArray()

        //Sign authentication value
        Signature ecdsaSign = Signature.getInstance("SHA384withECDSAinP1363Format")
        ecdsaSign.initSign(privateKey)
        ecdsaSign.update(authValue)
        byte[] signature = ecdsaSign.sign()
        String encodedSignature = Base64.getEncoder().encodeToString(signature)
        return encodedSignature
    }

    static String portCheck(String port) {
        if (port != null && port.isInteger()) {
            return ":${port}"
        } else {
            return ""
        }
    }

    static boolean isRunningInDocker() {
        if (StringUtils.containsIgnoreCase(System.getProperty('os.name'), 'linux')) {
            def cgroupFile = new File('/proc/1/cgroup')
            if (cgroupFile.exists() && cgroupFile.text.contains('docker')) {
                return true
            }
            def cgroupV2File = new File('/proc/1/mountinfo')
            if (cgroupV2File.exists() && cgroupV2File.text.contains('docker')) {
                return true
            }
        }
        return false
    }

    static boolean isLocal() {
        return !isRunningInDocker()
    }


    // prefix: "ory_rt_" = refresh token; "ory_at_" = access tokens; "ory_ac_" = authorization code
    static String generateOryToken(String prefix, String globalSecret = "testsecret") {
        // 1. 32 random bytes (fosite's default token entropy = 256 bits)
        byte[] randomBytes = new byte[32]
        new SecureRandom().nextBytes(randomBytes)

        // 2. HMAC-SHA512/256 over the random bytes, keyed with Hydra's system secret
        Mac mac = Mac.getInstance("HmacSHA512/256")
        mac.init(new SecretKeySpec(globalSecret.getBytes("UTF-8"), "HmacSHA512/256"))
        byte[] signature = mac.doFinal(randomBytes)

        // 3. base64url, NO padding, for both parts
        def b64 = Base64.urlEncoder.withoutPadding()
        String key = b64.encodeToString(randomBytes)
        String sig = b64.encodeToString(signature)

        // 4. prefix + key.signature
        return "${prefix}${key}.${sig}"
    }

    //Parses a duration in the format the admin service and Hydra use.
    static Duration parseDuration(String duration) {
        Matcher matcher = DURATION_PATTERN.matcher(duration ?: "")
        if (!duration || !matcher.matches()) {
            throw new IllegalArgumentException("Invalid duration string: \"${duration}\"")
        }
        return Duration.ofDays(durationPart(matcher, 1))
                .plusHours(durationPart(matcher, 2))
                .plusMinutes(durationPart(matcher, 3))
                .plusSeconds(durationPart(matcher, 4))
    }

    private static long durationPart(Matcher matcher, int group) {
        return matcher.group(group) == null ? 0L : matcher.group(group) as long
    }
}
