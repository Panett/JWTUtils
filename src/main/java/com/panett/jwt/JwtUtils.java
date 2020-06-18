package com.panett.jwt;

import io.jsonwebtoken.*;

import java.time.Instant;
import java.time.temporal.TemporalUnit;
import java.util.Date;
import java.util.Map;

public class JwtUtils {

    public static String encode(Map<String, Object> claims, int expirationTime, TemporalUnit temporalUnit) {
        Instant now = Instant.now();
        JwtBuilder jwtBuilder = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(Date.from(now));
        if(expirationTime>0) {
            jwtBuilder.setExpiration(Date.from(now.plus(expirationTime, temporalUnit)));
        }
        return jwtBuilder.compact();

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
