package camp.xit.google.api.credentials;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

class PrivateKeyDeserializer extends StdDeserializer<RSAPrivateKey> {

    public PrivateKeyDeserializer() {
        super(RSAPrivateKey.class);
    }

    @Override
    public RSAPrivateKey deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JsonProcessingException {
        try {
            return p.hasTextCharacters() ? getPrivateKey(p.getText()) : null;
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
    }

    public RSAPrivateKey getPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String encodedRawKey = privateKey
                .replace("-----BEGIN PRIVATE KEY-----\n", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("\n", "");
        byte[] decoded = Base64.getDecoder().decode(encodedRawKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(decoded));
    }

}
