package com.panett.jwt.rsa;

import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;

// openssl req -x509 -newkey rsa:4096 -keyout private_key.pem -out public_key.der
// openssl pkcs12 -export -out keyStore.p12 -inkey private_key.pem -in public_key.der -name "alias"
public class KeystoreLoader {

    public static KeyPair loadKeypairFromKeystore(String path, String password, String alias) throws Exception {

        KeyStore keyStore = KeyStore.getInstance("pkcs12");

        keyStore.load(new FileInputStream(path), password.toCharArray());

        Key key = keyStore.getKey(alias, password.toCharArray());
        if (key instanceof PrivateKey) {
            // Get certificate of public key
            Certificate cert = keyStore.getCertificate(alias);

            // Get public key
            PublicKey publicKey = cert.getPublicKey();

            // Return a key pair
            return new KeyPair(publicKey, (PrivateKey) key);
        }
        return null;
    }
}
