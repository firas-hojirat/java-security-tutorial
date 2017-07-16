package symmetric_crypto.mac;

//MAC, sometimes known as a tag, is a short piece of information used to authenticate a message—
//in other words, to confirm that the message came from the stated sender (its authenticity)
//and has not been changed.

//The MAC value protects both a message's data integrity as well as its authenticity,
//by allowing verifiers (who also possess the secret key) to detect any changes to the message content.

//HMAC is a specific type of message authentication code (MAC) involving a cryptographic hash function
//and a secret cryptographic key.

//HMAC does not encrypt the message. Instead, the message (encrypted or not) must be sent
//alongside the HMAC hash. Parties with the secret key will hash the message again themselves,
//and if it is authentic, the received and computed hashes will match.

//Authenticated Encryption - Encrypt then Mac (EtM)
//The plaintext is first encrypted, then a MAC is produced based on the resulting ciphertext.
//The ciphertext and its MAC are sent together.

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Hmac {

    private static final String ALG = "HmacSHA256";
    private static String key = "the shared secret key";
    private static String message = "the message";

    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {

        String hash = sendMessage(message);

        if (receiveMessage(message.toUpperCase(), hash))
            System.out.println("the message is NOT corrupted");
        else System.out.println("the message IS corrupted");
    }

    private static byte[] hash(String key, String message) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        Key secretKey = new SecretKeySpec(md.digest(key.getBytes("UTF-8")), ALG);

        Mac mac = Mac.getInstance(ALG);
        mac.init(secretKey);

        return mac.doFinal(message.getBytes("UTF-8"));
    }

    private static String sendMessage(String message) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {

        return Base64.getEncoder().encodeToString(hash(key, message));
    }

    private static boolean receiveMessage(String message, String hash) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        return Base64.getEncoder().encodeToString(hash(key, message)).equals(hash);
    }
}
