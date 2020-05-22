package camp.xit.google.api.credentials;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ClientAccessToken {

    @JsonProperty("access_token")
    private String tokenKey;
    @JsonProperty("token_type")
    private String tokenType;
    @JsonProperty("expires_in")
    private long expiresIn = -1;

    public ClientAccessToken() {
    }

    @Override
    public String toString() {
        if (OAuthConstants.BEARER_AUTHORIZATION_SCHEME.equalsIgnoreCase(getTokenType())) {
            return OAuthConstants.BEARER_AUTHORIZATION_SCHEME + " " + getTokenKey();
        }
        return super.toString();
    }

    public String getTokenKey() {
        return tokenKey;
    }

    public void setTokenKey(String tokenKey) {
        this.tokenKey = tokenKey;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }
}
