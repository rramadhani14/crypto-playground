package dev.ramadhani;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, KeyStoreException, OperatorCreationException, CertificateException, UnrecoverableKeyException {
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

        // Create certificate using bouncy castle because keystore only support saving certificate instead of public key
        // Even if the API support key, the runtime will throw an error, a private key always need certificate chain
        X500Name dnName = new X500Name("CN=Ramadhani");
        Date startDate = new Date();
        Date endDate = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                dnName,
                serialNumber,
                startDate,
                endDate,
                dnName,
                keyPair.getPublic()
        );
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(keyPair.getPrivate());
        X509CertificateHolder certificateHolder = certificateBuilder.build(signer);
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())
                .getCertificate(certificateHolder);

        // Create keystore to save keys
        KeyStore keyStore = KeyStore.getInstance("PKCS12"); //Use PKCS12 format instead of JKS
        keyStore.load(null, null);
        keyStore.setKeyEntry("my-private-key", keyPair.getPrivate(), null, new Certificate[]{certificate});
        try(FileOutputStream keystoreFos = new FileOutputStream("keystore.p12")) {
            keyStore.store(keystoreFos, "changeit".toCharArray());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        // Load keystore from file
        keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        try(FileInputStream keystoreFis = new FileInputStream("keystore.p12")) {
            keyStore.load(keystoreFis, "changeit".toCharArray());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        // Load keys from keystore
        privateKey = (PrivateKey) keyStore.getKey("my-private-key", null); //Password need to be null, because on saving key, we didn't use password.
        certificate = (X509Certificate) keyStore.getCertificateChain("my-private-key")[0];
        publicKey = certificate.getPublicKey();
        // Encrypt
        System.out.println(secretMessage);
        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        encryptedSecretMessageBytes = cipher.doFinal(secretMessageBytes);
        System.out.println(new String(encryptedSecretMessageBytes));
        // Decrypt
        cipher2 = Cipher.getInstance("RSA");
        cipher2.init(Cipher.DECRYPT_MODE, privateKey);
        decryptedSecretMessageBytes = cipher2.doFinal(encryptedSecretMessageBytes);
        System.out.println(new String(decryptedSecretMessageBytes));
    }
}