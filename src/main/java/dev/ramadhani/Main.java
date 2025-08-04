package dev.ramadhani;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        // Save files
        try(FileOutputStream pubFos = new FileOutputStream("public.pub");
        FileOutputStream pvtFos2 = new FileOutputStream("private")) {
            pubFos.write(publicKey.getEncoded());
            pvtFos2.write(privateKey.getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        // Load files
        File publicKeyFile = new File("public.pub");
        byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
        File privateKeyFile = new File("private");
        byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
        // Create keys
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKeyLoaded = keyFactory.generatePublic(publicKeySpec);
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKeyLoaded = keyFactory.generatePrivate(privateKeySpec);
        // Encrypt
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKeyLoaded);
        String secretMessage = "Hello World!";
        byte[] secretMessageBytes = secretMessage.getBytes();
        byte[] encryptedSecretMessageBytes = cipher.doFinal(secretMessageBytes);
        String encryptedSecretMessage = Base64.getEncoder().encodeToString(encryptedSecretMessageBytes);
        System.out.println(encryptedSecretMessage);
        // Decrypt
        Cipher cipher2 = Cipher.getInstance("RSA");
        cipher2.init(Cipher.DECRYPT_MODE, privateKeyLoaded);
        byte[] decryptedSecretMessageBytes = cipher2.doFinal(encryptedSecretMessageBytes);
        String decryptedSecretMessage = new String(decryptedSecretMessageBytes);
        System.out.println(decryptedSecretMessage);
    }
}