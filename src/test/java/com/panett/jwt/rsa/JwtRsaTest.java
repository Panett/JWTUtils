package com.panett.jwt.rsa;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.security.KeyPair;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class JwtRsaTest {

    private JwtRsa jwtRsa;
    private String jws;

    @Test
    @Order(1)
    void encode() throws Exception {

        jwtRsa = new JwtRsa();

        String path = "C:/Users/loren/Desktop/keyStore.p12";
        String password = "secretpassword";
        String alias = "alias";
        KeyPair keyPair = KeystoreLoader.loadKeypairFromKeystore(path, password, alias);
        String keyPairName = "keyPair1";
        jwtRsa.addKeyPair(keyPairName, keyPair);

        jws = jwtRsa.encode(keyPairName);
        System.out.println(jws);
    }

    @Test
    @Order(2)
    void verify() {
        KeyPair keyPair1 = jwtRsa.getKeyPair("keyPair1");
        jwtRsa.verify(jws, keyPair1.getPublic());
    }
}
