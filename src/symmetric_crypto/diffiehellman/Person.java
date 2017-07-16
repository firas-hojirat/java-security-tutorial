package symmetric_crypto.diffiehellman;

//The Diffie–Hellman key exchange method allows two parties that have no prior knowledge of each other
//to jointly establish a shared secret key over an insecure channel.
//This key can then be used to encrypt subsequent communications using a symmetric key cipher.

import symmetric_crypto.aes.Aes;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Person {

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private PublicKey receivedPublicKey;
    private String secretMessage;
    private Aes aes;

    public void encryptAndSendMessage(final String message, final Person person) {

        try {
            IvParameterSpec iv = aes.generateIV();
            String cipherText = aes.encrypt(message, iv);

            person.receiveAndDecryptMessage(cipherText, iv);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void generateCommonSecretKey() {

        try {
            final KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(receivedPublicKey, true);

            aes = new Aes(keyAgreement.generateSecret());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void generateKeys() {

        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(2048);

            final KeyPair keyPair = keyPairGenerator.generateKeyPair();

            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public byte[] getPublicKey() {

        return publicKey.getEncoded();
    }

    public void receiveAndDecryptMessage(String message, IvParameterSpec iv) {

        try {
            secretMessage = aes.decrypt(message, iv);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void receivePublicKeyFrom(final Person person) {

        try {
            KeyFactory kf = KeyFactory.getInstance("DH");
            //X509 represents encoding of a public key
            //PKCS8 represents enconding of a private key
            receivedPublicKey = kf.generatePublic(new X509EncodedKeySpec(person.getPublicKey()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    public void whisperTheSecretMessage() {

        System.out.println(secretMessage);
    }
}
