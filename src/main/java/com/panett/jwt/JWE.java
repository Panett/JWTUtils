package com.panett.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

public class JWE {

    private RSAEncrypter rsaEncrypter;
    private RSADecrypter rsaDecrypter;

    public JWE(KeyPair keyPair) {
       rsaEncrypter = new RSAEncrypter((RSAPublicKey) keyPair.getPublic());
       rsaDecrypter = new RSADecrypter(keyPair.getPrivate());
    }

    public String encrypt(String jws) throws Exception {
        // JWEAlgorithm alg = JWEAlgorithm.RSA_OAEP_256;
        // EncryptionMethod enc = EncryptionMethod.A128CBC_HS256;

        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .contentType("JWT")
                        .build(),
                new Payload(jws));
        jwe.encrypt(rsaEncrypter);
        return jwe.serialize();
    }

    public String decrypt(String jweString) throws Exception {
        JWEObject jwe = JWEObject.parse(jweString);
        jwe.decrypt(rsaDecrypter);
        return jwe.getPayload().toString();
    }
}
