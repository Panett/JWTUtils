package com.lorenzo.jwt.rsa;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

public class JwtRsa {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        testJWTWithRsa();
    }

    public static void testJWTWithRsa() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(2048);

        KeyPair kp = keyGenerator.genKeyPair();
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        String encodedPublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        System.out.println(convertToPublicKey(encodedPublicKey));
        String token = generateJws(privateKey);
        System.out.println("\nTOKEN:");
        System.out.println(token);
        printStructure(token, publicKey);
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

    public static void printStructure(String token, PublicKey publicKey) {

        Jws<Claims> jws = Jwts.parserBuilder().
                setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token);

        System.out.println("Header     : " + jws.getHeader());
        System.out.println("Body       : " + jws.getBody());
        System.out.println("Signature  : " + jws.getSignature());
    }

    private static String convertToPublicKey(String key){
        return "-----BEGIN PUBLIC KEY-----\n" +
                key +
                "\n-----END PUBLIC KEY-----";
    }

}
