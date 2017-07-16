package symmetric_crypto.aes;

import javax.crypto.spec.IvParameterSpec;

public class Test {

	public static void main(String[] args) throws Exception {

		Aes aes = new Aes("1234567867910111213141516");
		IvParameterSpec iv = aes.generateIV();

        String plainText = "Hello, World!";
        System.out.println("Plain Text: " + plainText);

        String cipherText = aes.encrypt(plainText, iv);
        System.out.println("Cipher Text: " + cipherText);

        System.out.println("Decrypted Text: " + aes.decrypt(cipherText, iv));
	}

}
