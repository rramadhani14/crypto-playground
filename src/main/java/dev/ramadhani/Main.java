package dev.ramadhani;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Base64;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, FileNotFoundException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
//        try(FileOutputStream pubFos = new FileOutputStream("public.pub");
//        FileOutputStream pvtFos2 = new FileOutputStream("private");) {
//            pubFos.write(publicKey.getEncoded());
//            pvtFos2.write(privateKey.getEncoded());
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        String secretMessage = "Hello World!";
        byte[] secretMessageBytes = secretMessage.getBytes();
        byte[] encryptedSecretMessageBytes = cipher.doFinal(secretMessageBytes);
        String encryptedSecretMessage = Base64.getEncoder().encodeToString(encryptedSecretMessageBytes);
        System.out.println(encryptedSecretMessage);
        Cipher cipher2 = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSecretMessageBytes = cipher.doFinal(encryptedSecretMessageBytes);
        String decryptedSecretMessage = new String(decryptedSecretMessageBytes);
        System.out.println(decryptedSecretMessage);
    }
}