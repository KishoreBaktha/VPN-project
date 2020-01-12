import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class SessionEncrypter {
    private SessionKey sessionKey;
    private Cipher cipher;
    private CipherOutputStream outputstream;

    public SessionEncrypter(Integer keyLength) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        this.sessionKey = new SessionKey(keyLength);
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        this.cipher.init(1, this.sessionKey.getSecretKey());
    }

    public SessionEncrypter(String keyString, String ivString) {
        try {
            this.sessionKey = new SessionKey(keyString);
            this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
            byte[] iv = Base64.getDecoder().decode(ivString);
            IvParameterSpec pmSpec = new IvParameterSpec(iv);
            this.cipher.init(1, this.sessionKey.getSecretKey(), pmSpec);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }

    public String encodeKey() {
        return this.sessionKey.encodeKey();
    }

    public byte[] getKeyBytes() {
        return this.sessionKey.getEncoded();
    }

    public String encodeIV() {
        byte[] iv = this.cipher.getIV();
        return Base64.getEncoder().encodeToString(iv);
    }

    public byte[] getIVBytes() {
        return this.cipher.getIV();
    }

    CipherOutputStream openCipherOutputStream(OutputStream outputStream) {
        this.outputstream = new CipherOutputStream(outputStream, this.cipher);
        return this.outputstream;
    }

    CipherOutputStream getCipherOutputStream() {
        return this.outputstream;
    }
}