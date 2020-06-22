package com.panett.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.time.temporal.TemporalUnit;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JWS {

    public static String encode(String keyString, Map<String, Object> claims, int expirationTime, TemporalUnit temporalUnit) {
        return initJwtBuilder(claims, expirationTime, temporalUnit)
                .signWith(Keys.hmacShaKeyFor(getHash(keyString)))
                .compact();
    }

    public static String encode(PrivateKey privateKey, Map<String, Object> claims, int expirationTime, TemporalUnit temporalUnit) {
        return initJwtBuilder(claims, expirationTime, temporalUnit)
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    public static Jws<Claims> verify(String jws, String keyString) {
        return Jwts.parserBuilder()
                .setSigningKey(getHash(keyString))
                .build()
                .parseClaimsJws(jws);
    }

    public static Jws<Claims> verify(String jws, PublicKey publicKey) {
        return Jwts.parserBuilder().
                setSigningKey(publicKey)
                .build()
                .parseClaimsJws(jws);
    }

    public static Jwt<Header, Claims> decode(String jws) {
        int i = jws.lastIndexOf('.');
        String jwt = jws.substring(0, i+1);
        return Jwts.parserBuilder().build().parseClaimsJwt(jwt);
    }

    public static Map<String, String> decodeIgnoringExpiration(String jws) {
        Base64.Decoder decoder = Base64.getUrlDecoder();
        String[] parts = jws.split("\\.");
        Map<String, String> decoded = new HashMap<>();
        decoded.put("Headers", new String(decoder.decode(parts[0])));
        decoded.put("Payload", new String(decoder.decode(parts[1])));
        return decoded;
    }

    private static JwtBuilder initJwtBuilder(Map<String, Object> claims, int expirationTime, TemporalUnit temporalUnit) {
        Instant now = Instant.now();
        JwtBuilder jwtBuilder = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(Date.from(now));
        if(expirationTime>0) {
            jwtBuilder.setExpiration(Date.from(now.plus(expirationTime, temporalUnit)));
        }
        return jwtBuilder;
    }

    private static byte[] getHash(String secret) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(secret.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
}
