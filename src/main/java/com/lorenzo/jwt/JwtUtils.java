package com.lorenzo.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;

import java.time.Instant;
import java.time.temporal.TemporalUnit;
import java.util.Date;
import java.util.Map;

public class JwtUtils {

    public static String encode(String issuer, Map<String, Object> claims, int expirationTime, TemporalUnit temporalUnit) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setClaims(claims)
                .setIssuer(issuer)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plus(expirationTime, temporalUnit)))
                .compact();
    }

    public static Jwt<Header, Claims> decodeIgnoringSignature(String jws) {
        int i = jws.lastIndexOf('.');
        String withoutSignature = jws.substring(0, i+1);
        return Jwts.parserBuilder().build().parseClaimsJwt(withoutSignature);
    }

    public static Jwt<Header, Claims> decodeNoSignature(String jwt) {
        return Jwts.parserBuilder()
                .build()
                .parseClaimsJwt(jwt);
    }

}
