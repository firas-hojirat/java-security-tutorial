package symmetric_crypto.aes;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class Aes implements SymmetricKey{

	public static final int IV_LENGTH = 16;
	private static final String TRANSFORMATION = "Aes/CBC/PKCS5Padding";
	private byte[] iv;
	private SecureRandom sr;
	private MessageDigest md;
	private SecretKey key;

	private Aes() throws NoSuchAlgorithmException, UnsupportedEncodingException{
        //key size 256 requires java security extension.
        this.md = MessageDigest.getInstance("SHA-256");
        this.iv = new byte[IV_LENGTH];
        this.sr = new SecureRandom();
    }
	
	public Aes(String keyString) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		this();

		//generate only one key using SHA-256 hashing.
		this.key = new SecretKeySpec(md.digest(keyString.getBytes("UTF-8")), "Aes");
	}

	public Aes(byte[] secretKey) throws NoSuchAlgorithmException, UnsupportedEncodingException{
	    this();

        //generate only one key using SHA-256 hashing.
        this.key = new SecretKeySpec(md.digest(secretKey), "Aes");
    }
	
	@Override
	public SecretKey getKey() throws UnsupportedEncodingException {
		return key;
	}
	
	@Override
	public IvParameterSpec generateIV() throws UnsupportedEncodingException {
		sr.nextBytes(iv); //generate random iv with length IV_LENGTH
		return new IvParameterSpec(iv);
	}
	
	@Override
	public String encrypt(String plainText, IvParameterSpec iv) throws Exception {
		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(Cipher.ENCRYPT_MODE, getKey(), iv);

		//encodes(converts) String to bytes, new String() is used to decode it(re convert it back).
		byte[] plainData = plainText.getBytes("UTF-8");
		byte[] cipherData = cipher.doFinal(plainData);
		//encodes(converts) bytes to String, Base64.Decoder is used to decode it(re convert it back).
		String cipherText = Base64.getEncoder().encodeToString(cipherData);

		return cipherText;
	}

    @Override
    public String decrypt(String cipherText, IvParameterSpec iv) throws Exception{
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, getKey(), iv);
        return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)), "UTF-8");
    }

	@Override
	public byte[] encrypt(byte[] rawData, IvParameterSpec iv) throws Exception {
		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(Cipher.ENCRYPT_MODE, getKey(), iv);
		return cipher.doFinal(rawData);
	}

    @Override
    public byte[] decrypt(byte[] cipherData, IvParameterSpec iv) throws Exception {
        Cipher c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.DECRYPT_MODE, getKey(), iv);
        return c.doFinal(cipherData);
    }
}
