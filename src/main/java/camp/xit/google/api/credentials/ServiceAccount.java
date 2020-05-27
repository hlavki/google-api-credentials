package camp.xit.google.api.credentials;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;

public class ServiceAccount {

    private String type;
    @JsonProperty("project_id")
    private String projectId;
    @JsonProperty("private_key_id")
    private String privateKeyId;
    @JsonProperty("private_key")
    @JsonDeserialize(using = PrivateKeyDeserializer.class)
    private RSAPrivateKey privateKey;
    @JsonProperty("client_email")
    private String clientEmail;
    @JsonProperty("client_id")
    private String clientId;
    @JsonProperty("auth_uri")
    private String authUri;
    @JsonProperty("token_uri")
    private String tokenUri;
    @JsonProperty("auth_provider_x509_cert_url")
    private String authProviderUrl;
    @JsonProperty("client_x509_cert_url")
    private String clientCertUrl;

    public ServiceAccount() {
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getProjectId() {
        return projectId;
    }

    public void setProjectId(String projectId) {
        this.projectId = projectId;
    }

    public String getPrivateKeyId() {
        return privateKeyId;
    }

    public void setPrivateKeyId(String privateKeyId) {
        this.privateKeyId = privateKeyId;
    }

    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(RSAPrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public String getClientEmail() {
        return clientEmail;
    }

    public void setClientEmail(String clientEmail) {
        this.clientEmail = clientEmail;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getAuthUri() {
        return authUri;
    }

    public void setAuthUri(String authUri) {
        this.authUri = authUri;
    }

    public String getTokenUri() {
        return tokenUri;
    }

    public void setTokenUri(String tokenUri) {
        this.tokenUri = tokenUri;
    }

    public String getAuthProviderUrl() {
        return authProviderUrl;
    }

    public void setAuthProviderUrl(String authProviderUrl) {
        this.authProviderUrl = authProviderUrl;
    }

    public String getClientCertUrl() {
        return clientCertUrl;
    }

    public void setClientCertUrl(String clientCertUrl) {
        this.clientCertUrl = clientCertUrl;
    }
}
