package camp.xit.google.api.credentials;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.apache.http.Consts;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.StatusLine;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class GoogleCredentials {

    private static final Logger LOG = LoggerFactory.getLogger(GoogleCredentials.class);
    private static final int TOKEN_EXPIRATION = 3600;

    private final ExpirationSupplier<ClientAccessToken> tokenCache;
    private final ObjectMapper objMapper;
    private final CloseableHttpClient httpClient;
    private final ServiceAccount serviceAccount;
    private final String scopes;

    public GoogleCredentials(String serviceAccountFile, String... scopes) {
        this(new File(serviceAccountFile), scopes);
    }

    public GoogleCredentials(File serviceAccountFile, String... scopes) {
        this(serviceAccountFile, HttpClients.createDefault(), scopes);
    }

    public GoogleCredentials(File serviceAccountFile, CloseableHttpClient httpClient, String... scopes) {
        this.objMapper = getObjMapper();
        this.httpClient = httpClient;
        this.serviceAccount = readServiceAccount(serviceAccountFile);
        this.tokenCache = new ExpirationSupplier<>(this::readToken, TOKEN_EXPIRATION - 3, TimeUnit.SECONDS);
        this.scopes = String.join("", Arrays.asList(scopes));
    }

    public ClientAccessToken getAccessToken() {
        return tokenCache.get();
    }

    private ObjectMapper getObjMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.disable(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES);
        return mapper;
    }

    private ServiceAccount readServiceAccount(File serviceAccountFile) {
        try {
            return objMapper.readValue(serviceAccountFile, ServiceAccount.class);
        } catch (IOException e) {
            throw new IllegalArgumentException("Cannot read service account file", e);
        }
    }

    private ClientAccessToken readToken(ClientAccessToken previousValue, long lastModification) {
        LOG.info("Refreshing access token");

        Instant now = Instant.now();
        Algorithm algorithm = Algorithm.RSA256(null, serviceAccount.getPrivateKey());
        String encodedToken = JWT.create()
                .withIssuer(serviceAccount.getClientEmail())
                .withAudience(serviceAccount.getTokenUri())
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(now.plusSeconds(TOKEN_EXPIRATION)))
                .withClaim("scope", scopes)
                .sign(algorithm);

        List<NameValuePair> formparams = new ArrayList<NameValuePair>();
        formparams.add(new BasicNameValuePair("grant_type", OAuthConstants.JWT_BEARER_GRANT));
        formparams.add(new BasicNameValuePair("assertion", encodedToken));
        UrlEncodedFormEntity entity = new UrlEncodedFormEntity(formparams, Consts.UTF_8);

        HttpPost request = new HttpPost(URI.create(serviceAccount.getTokenUri()));
        request.setEntity(entity);
        request.setHeader("Content-Type", "application/x-www-form-urlencoded");
        request.setHeader("Accept", "application/json");

        try {
            CloseableHttpResponse response = httpClient.execute(request);
            StatusLine statusLine = response.getStatusLine();
            if (statusLine.getStatusCode() == HttpStatus.SC_OK) {
                try ( InputStream in = response.getEntity().getContent()) {
                    return objMapper.readValue(in, ClientAccessToken.class);
                }
            } else {
                throw new RuntimeException("Cannot obtain access token. Status: " + statusLine);
            }
        } catch (IOException e) {
            throw new RuntimeException("Cannot read access token", e);
        }
    }
}
