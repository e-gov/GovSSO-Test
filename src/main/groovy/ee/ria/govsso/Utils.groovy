package ee.ria.govsso

import com.fasterxml.jackson.databind.ObjectMapper
import io.qameta.allure.Allure
import org.spockframework.lang.Wildcard
import io.restassured.response.Response

class Utils {

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

    static void storeTaraServiceUrltoflow(Flow flow, String url) {
        URL rawUrl = new URL(url)
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
}
