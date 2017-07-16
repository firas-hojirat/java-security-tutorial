package symmetric_crypto.aes;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.UnsupportedEncodingException;

public interface SymmetricKey {
	
	SecretKey getKey() throws UnsupportedEncodingException;

	IvParameterSpec generateIV() throws UnsupportedEncodingException;

	byte[] encrypt(byte[] rawData, IvParameterSpec iv) throws Exception;

	String encrypt(String plainText, IvParameterSpec iv) throws Exception;

	byte[] decrypt(byte[] cipherData, IvParameterSpec iv) throws Exception;

	String decrypt(String cipherText, IvParameterSpec iv) throws Exception;

}
