import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.util.Base64;

class SessionKey {

    private SecretKey secretKey;

    SessionKey(int keylength) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(keylength);
            secretKey = keyGenerator.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    SessionKey(String encodedkey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedkey);
        secretKey = new SecretKeySpec(decodedKey, "AES");
    }

    String encodeKey() {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    SecretKey getSecretKey() {
        return secretKey;
    }

    public byte[] getEncoded() {
        return this.secretKey.getEncoded();
    }
}