import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class SessionDecrypter {
    private SessionKey sessionKey;
    private Cipher cipher;
    private CipherInputStream inputstream;

    public SessionDecrypter(String keyString, String ivString) {
        try {
            this.sessionKey = new SessionKey(keyString);
            this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
            byte[] iv = Base64.getDecoder().decode(ivString);
            IvParameterSpec pmSpec = new IvParameterSpec(iv);
            this.cipher.init(2, this.sessionKey.getSecretKey(), pmSpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String encodeKey() {
        return this.sessionKey.encodeKey();
    }

    public String encodeIV() {
        byte[] iv = this.cipher.getIV();
        return Base64.getEncoder().encodeToString(iv);
    }

    CipherInputStream openCipherInputStream(InputStream inputStream) {
        this.inputstream = new CipherInputStream(inputStream, this.cipher);
        return this.inputstream;
    }
}


