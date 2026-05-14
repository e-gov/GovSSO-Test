package ee.ria.govsso.model

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import groovy.transform.Canonical
import groovy.transform.EqualsAndHashCode

@EqualsAndHashCode
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
class Client {

    @JsonProperty("client_id")
    String clientId

    @JsonProperty("client_name")
    ClientName clientName

    @JsonProperty("client_short_name")
    ClientShortName clientShortName

    @JsonProperty("institution_metainfo")
    InstitutionMetainfo institutionMetainfo

    @JsonProperty("redirect_uris")
    Set<String> redirectUris

    @JsonProperty("token_request_allowed_ip_addresses")
    Set<String> tokenRequestAllowedIpAddresses

    @JsonProperty("token_endpoint_auth_method")
    String tokenEndpointAuthMethod

    @JsonProperty("post_logout_redirect_uris")
    Set<String> postLogoutRedirectUris

    @JsonProperty("backchannel_logout_uri")
    String backchannelLogoutUri

    Set<String> scope

    @JsonProperty(value = "_systemTest_secret", access = JsonProperty.Access.WRITE_ONLY)
    String secret

    String description

    @JsonProperty("info_notification_emails")
    Set<String> infoNotificationEmails

    @JsonProperty("client_contacts")
    Set<ClientContact> clientContacts

    @JsonProperty("sla_notification_emails")
    Set<String> slaNotificationEmails

    @JsonProperty("is_user_consent_required")
    Boolean isUserConsentRequired

    @JsonProperty("client_type")
    ClientType clientType = ClientType.DEFAULT

    @JsonProperty("session_lifespan")
    String sessionLifespan

    String getRedirectUri() {
        redirectUris.first()
    }

    String getPostLogoutRedirectUri() {
        postLogoutRedirectUris.first()
    }

    String getFullBaseUrl() {
        URI uri = URI.create(redirectUri)
        "${uri.scheme}://${uri.authority}"
    }
}

@Canonical
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
class ClientName {
    String et
    String en
    String ru
}

@Canonical
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
class ClientShortName {
    String et
    String en
    String ru
}

@Canonical
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
class InstitutionMetainfo {
    String name

    @JsonProperty("registry_code")
    String registryCode
    InstitutionType type
}

@Canonical
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
class InstitutionType {
    String type
}

@Canonical
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
class ClientContact {
    String name
    String email
    String phone
    String department
}
