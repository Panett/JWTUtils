package com.panett.jwt.rsa;

import io.jsonwebtoken.*;
import lombok.extern.java.Log;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.time.temporal.TemporalUnit;
import java.util.Date;
import java.util.Map;

@Log
public class JwtRsa {

    public static String encode(PrivateKey privateKey, Map<String, Object> claims, int expirationTime, TemporalUnit temporalUnit) {
        Instant now = Instant.now();
        JwtBuilder jwtBuilder = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(Date.from(now))
                .signWith(privateKey, SignatureAlgorithm.RS256);
        if(expirationTime>0) {
            jwtBuilder.setExpiration(Date.from(now.plus(expirationTime, temporalUnit)));
        }
        return jwtBuilder.compact();
    }

    public static void verify(String token, PublicKey publicKey) {
        log.info("\nTOKEN: " + token);
        Jws<Claims> jws = Jwts.parserBuilder().
                setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token);
        log.info("Header     : " + jws.getHeader() +
                "\nBody       : " + jws.getBody() +
                "\nSignature  : " + jws.getSignature());
    }



}
