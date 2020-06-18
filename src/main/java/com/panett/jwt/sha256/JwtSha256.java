package com.panett.jwt.sha256;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.TemporalUnit;
import java.util.Date;
import java.util.Map;

public class JwtSha256 {

    public static String encodeAndSign(String keyString, Map<String, Object> claims, int expirationTime, TemporalUnit temporalUnit) throws NoSuchAlgorithmException {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] secret = digest.digest(keyString.getBytes(StandardCharsets.UTF_8));

        Instant now = Instant.now();

        JwtBuilder jwtBuilder = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(Date.from(now))
                .signWith(Keys.hmacShaKeyFor(secret));
        if(expirationTime>0) {
            jwtBuilder.setExpiration(Date.from(now.plus(expirationTime, temporalUnit)));
        }
        return jwtBuilder.compact();
    }

    public static Jws<Claims> verify(String jwsToVerify, String keyString) throws NoSuchAlgorithmException {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] secret = digest.digest(keyString.getBytes(StandardCharsets.UTF_8));

        return Jwts.parserBuilder()
                .setSigningKey(secret)
                .build()
                .parseClaimsJws(jwsToVerify);
    }

}
