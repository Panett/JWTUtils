package com.panett.jwt.rsa;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JwtRsa {

    private Map<String, KeyPair> keypairs;

    public JwtRsa() {
        this.keypairs = new HashMap<>();
    }

    public void addKeyPair(String name, KeyPair keyPair) {
        keypairs.put(name, keyPair);
    }

    public void addKeyPairs(Map<String, KeyPair> keypairs) {
        this.keypairs.putAll(keypairs);
    }

    public KeyPair getKeyPair(String keyPairName) {
        return keypairs.getOrDefault(keyPairName, null);
    }

    public String encode(String keyPairName) {
        if(keypairs.containsKey(keyPairName)) {
            return generateJws(keypairs.get(keyPairName).getPrivate());
        } else {
            System.out.println("ERRORE: KeyPair " + keyPairName + " non trovato");
        }
        return keyPairName;
    }

    public static String generateJws(PrivateKey privateKey) {

        Instant now = Instant.now();

        return Jwts.builder()
                .setSubject("Lorenzo Panetta")
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plus(1, ChronoUnit.MINUTES)))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    public void verify(String token, PublicKey publicKey) {
        System.out.println("\nTOKEN: " + token);
        Jws<Claims> jws = Jwts.parserBuilder().
                setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token);

        System.out.println("Header     : " + jws.getHeader());
        System.out.println("Body       : " + jws.getBody());
        System.out.println("Signature  : " + jws.getSignature());
    }

}
