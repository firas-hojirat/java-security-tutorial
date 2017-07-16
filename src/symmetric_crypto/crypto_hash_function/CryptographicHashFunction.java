package symmetric_crypto.crypto_hash_function;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

//It is a mathematical algorithm that maps data of arbitrary size to a bit string of a fixed size (a hash function)
//it is deterministic so the same message always results in the same hash.
//it is infeasible to generate a message from its hash value except by trying all possible messages.

//Cryptographic hash functions have many information-security applications,
//notably in digital signatures, message authentication codes (MACs), and other forms of authentication.

//hash functions provide only integrity, they do not provide authenticity.
public class CryptographicHashFunction {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String message = "message";
        String sentMessage = sendMessage(message);
        if(receiveMessage(message, sentMessage))
            System.out.println("message is NOT corrupted");
        else System.out.println("message IS corrupted");


    }

    private static String sendMessage(String message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String sentMessage = Base64.getEncoder().encodeToString(md.digest(message.getBytes()));
        return sentMessage;
    }

    //anyone can generate a hash which loses its purpose for authenticating.
    //whereas in MAC not everyone can since it requires a secret key.
    private static boolean receiveMessage(String message, String hash) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String receivedMessage = Base64.getEncoder().encodeToString(md.digest(message.getBytes()));
        return receivedMessage.equals(hash);
    }
}
