package com.panett.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import org.junit.jupiter.api.Test;

import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

class JwtUtilsTest {

    @Test
    void encode() {
        System.out.println("\n\n- - - - - - - - - - ENCODE - - - - - - - - - - - -");
        Map<String, Object> claims = new HashMap<>();
        claims.put("issuer", "Lorenzo Panetta");
        String jws = JwtUtils.encode(claims, 0, ChronoUnit.MINUTES);
        System.out.println(jws);
    }

    @Test
    void decodeIgnoringSignature() {
        System.out.println("\n\n- - - - - - - DECODE IGNORING SIGNATURE - - - - - -");
        String jws = "eyJhbGciOiJIUzI1NiJ9.eyJpc3N1ZXIiOiJMb3JlbnpvIFBhbmV0dGEiLCJpYXQiOjE1OTI0OTM2MTB9.ReD5MW0sEJfUf2IKgutfZ_7UMM42tKJA96rNdx62M4k";
        Jwt<Header, Claims> decoded = JwtUtils.decodeIgnoringSignature(jws);
        System.out.println(
                "HEADER: \t" + decoded.getHeader() +
                        "\nBODY: \t\t" + decoded.getBody());
    }

    @Test
    void decodeNoSignature() {
        System.out.println("\n\n- - - - - - - - DECODE NO SIGNATURE - - - - - - - -");
        String jwt = "eyJhbGciOiJub25lIn0.eyJpc3N1ZXIiOiJMb3JlbnpvIFBhbmV0dGEiLCJpYXQiOjE1OTI0OTM1OTB9.";
        Jwt<Header, Claims> decoded = JwtUtils.decodeIgnoringSignature(jwt);
        System.out.println(
                "HEADER: \t" + decoded.getHeader() +
                        "\nBODY: \t\t" + decoded.getBody());
    }
}