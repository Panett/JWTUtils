package com.panett.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class JWE {

    public static void encrypt() throws Exception {
        JWEAlgorithm alg = JWEAlgorithm.RSA_OAEP_256;
        EncryptionMethod enc = EncryptionMethod.A128CBC_HS256;

        // Generate an RSA key pair
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        KeyPair rsaKeyPair = rsaGen.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

        // Generate the preset Content Encryption (CEK) key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(enc.cekBitLength());
        SecretKey cek = keyGenerator.generateKey();

        // Encrypt the JWE with the RSA public key + specified AES CEK
        JWEObject jwe = new JWEObject(
                new JWEHeader(alg, enc),
                new Payload("Hello, world!"));
        jwe.encrypt(new RSAEncrypter(rsaPublicKey, cek));
        String jweString = jwe.serialize();

        // Decrypt the JWE with the RSA private key
        jwe = JWEObject.parse(jweString);
        jwe.decrypt(new RSADecrypter(rsaPrivateKey));
        System.out.println(jwe.getPayload());

        // Decrypt JWE with CEK directly, with the DirectDecrypter in promiscuous mode
        jwe = JWEObject.parse(jweString);
        jwe.decrypt(new DirectDecrypter(cek, true));
        System.out.println(jwe.getPayload());
    }
}
