package com.mycompany.encryption;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import org.apache.commons.lang.StringUtils;



public class SecurityService {
    
    //Generates secret key with the algorithm given AES o DES
    public SecretKey generateSymetricKey(String algorithm) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance(algorithm);
        if (algorithm.equals("AES")) generator.init(128); // The algorithm key size in number of bits
        else if (algorithm.equals("DES")) generator.init(56);
        SecretKey secKey = generator.generateKey(); 
        return secKey;
    }
    
    public Cipher generateCipherSymm(String algorithm, SecretKey secKey, int mode)throws Exception{
        Cipher encryptCipher = Cipher.getInstance(algorithm);
        switch (mode){
            case 1:
                encryptCipher.init(Cipher.ENCRYPT_MODE, secKey);
                break;
            case 2:
                encryptCipher.init(Cipher.DECRYPT_MODE, secKey);
                break;
        }
        return encryptCipher;
    }
    
    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        //System.out.format("Public Key created: \"%s\" %n Private Key created: \"%s\" %n", pair.getPublic(), pair.getPrivate());
        return pair;
    }
    
    public Cipher generateCipherEncryptRSA(PublicKey publicKey) throws Exception{
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        //System.out.println("Cipher for encryption created");
        return encryptCipher;
    }
    
    public Cipher generateCipherDecryptRSA(PrivateKey privateKey) throws Exception{
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        //System.out.println("Cipher for decryption created");
        return encryptCipher;
    }
    
    public String encrypt(String textToEncrypt, Cipher cipherEncrypt) throws Exception {
        byte[] textToEncriptBytes = textToEncrypt.getBytes("UTF-8");
        byte[] cipherText = cipherEncrypt.doFinal(textToEncriptBytes);
        return Base64.getEncoder().encodeToString(cipherText);
    }
    
    public  String decrypt(String textToDecrypt, Cipher cipherDecrypt) throws Exception {
        byte[] textToDecryptBytes = Base64.getDecoder().decode(textToDecrypt);
        return new String(cipherDecrypt.doFinal(textToDecryptBytes), "UTF-8");
    }
    
    public String sign(String textToSign, PrivateKey privateKey)throws Exception{
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(textToSign.getBytes("UTF-8"));
        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);
    }
    
    public boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes("UTF-8"));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }
    
    
    public String decryptWithSymmKey(String textToDecrypt, String decryptedSymmKey, String algorithm) throws Exception{
        byte[] decryptedKey  = Base64.getDecoder().decode(decryptedSymmKey);
        byte[] textToDecryptBytes  = Base64.getDecoder().decode(textToDecrypt);
        SecretKey originalKey = new SecretKeySpec(decryptedKey , 0, decryptedKey.length, algorithm);
        Cipher cipherDecrypt = generateCipherSymm(algorithm, originalKey, 2);
        return new String(cipherDecrypt.doFinal(textToDecryptBytes), "UTF-8");
    }
    
    
    //Methods implemented for testing pursposes
    
    public void RSAOnlyEncryptAndDecrypt(String data) throws Exception{
        KeyPair keyPair = generateKeyPair();
        Cipher cipherEncrypt = generateCipherEncryptRSA(keyPair.getPublic());
        Cipher cipherDecrypt = generateCipherDecryptRSA(keyPair.getPrivate());
        String encryptedText = encrypt(data, cipherEncrypt);
        System.out.format("Data \"%s\"%n was encrypted as:%n  \"%s\" %n", data, encryptedText);
        String decryptedText = decrypt(encryptedText, cipherDecrypt);
        System.out.format("Data \"%s\"%n was decrypted as:%n  \"%s\" %n", encryptedText, decryptedText);
    }
    
    public void DESorAESOnlyEncryptAndDecrypt(String data, String encript_scheme) throws Exception{
        SecretKey secKey = generateSymetricKey(encript_scheme);
        Cipher cipherEncrypt = generateCipherSymm(encript_scheme, secKey, 1);
        Cipher cipherDecrypt = generateCipherSymm(encript_scheme, secKey, 2);
        String encryptedText = encrypt(data, cipherEncrypt);
        System.out.format("Data \"%s\"%n was encrypted as:%n  \"%s\" %n", data, encryptedText);
        String decryptedText = decrypt(encryptedText, cipherDecrypt);
        System.out.format("Data \"%s\"%n was decrypted as:%n  \"%s\" %n", encryptedText, decryptedText);
    }
    
    public void DESwithRSAEncryptAndDecrypt(String data, String encript_scheme) throws Exception{
        
        //1.- Generate the symmetric key as AES or DES
        SecretKey secKey = generateSymetricKey(encript_scheme);
        //2.- Generate the cipher with the symmetric key for encryption mode
        Cipher cipherEncryptSymm = generateCipherSymm(encript_scheme, secKey, 1);
        //3.- Encrypt the data with the cipher created previously
        String encryptedText = encrypt(data, cipherEncryptSymm);
        System.out.format("Data \"%s\"%n was encrypted as:%n  \"%s\" %n", data, encryptedText);
        //4.- Generate the Public Key and Private Key for RSA encryption scheme
        KeyPair keyPair = generateKeyPair();
        //5.- Generate the cipher with the asymmetric key (pair of keys) for encryption/decryption mode
        Cipher cipherEncryptRSA = generateCipherEncryptRSA(keyPair.getPublic());
        Cipher cipherDecryptRSA = generateCipherDecryptRSA(keyPair.getPrivate());
        //6.- Encrypt the Symmetric Key with the cipher created under RSA
        String encryptedSymmKey = encrypt(Base64.getEncoder().encodeToString(secKey.getEncoded()), cipherEncryptRSA);
        //7.- Decrypt the Encrypted Symmetric Key with the cipher created under RSA
        String decryptedSymmKey = decrypt(encryptedSymmKey, cipherDecryptRSA);
        //8.- Decrypt the data by using the Decrypted Symmetric key
        String decryptedText = decryptWithSymmKey(encryptedText, decryptedSymmKey, encript_scheme);
        System.out.format("Data \"%s\"%n was decrypted as:%n  \"%s\" %n", encryptedText, decryptedText);
    }
    
    public void ConvertwithSHA(String data) throws Exception{
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(data.getBytes());
       
        byte byteData[] = md.digest();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < byteData.length; i++) {
         sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
        }
        System.out.format("Data \"%s\"%n was hased as:%n  \"%s\" %n", data, sb.toString());        
    }
    
    public void ConvertwithHMAC(String data) throws Exception{
        String key = "the shared secret key here";
	    String message = "the message to hash here";
	    
	    Mac hasher = Mac.getInstance("HmacSHA256");
	    hasher.init(new SecretKeySpec(key.getBytes(), "HmacSHA256"));
	    
	    byte[] hash = hasher.doFinal(message.getBytes());
	    
	    // to lowercase hexits
	    String computeHmac=DatatypeConverter.printHexBinary(hash);
	    
	    // to base64
	    //DatatypeConverter.printBase64Binary(hash);
        System.out.format("Data \"%s\"%n was hased as:%n  \"%s\" %n", data, computeHmac);        
    }
    
}
