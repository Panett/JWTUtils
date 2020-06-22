package com.panett.jwt;

import io.jsonwebtoken.Jwt;
import org.junit.jupiter.api.Test;

import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

class JwtTest {

    @Test
    void encode() {
        System.out.println("\n\n- - - - - - - - - - ENCODE - - - - - - - - - - - -");
        Map<String, Object> claims = new HashMap<>();
        claims.put("issuer", "Lorenzo Panetta");
        String jws = JWT.encode(claims, 0, ChronoUnit.MINUTES);
        System.out.println(jws);
    }

    @Test
    void decodeNoSignature() {
        System.out.println("\n\n- - - - - - - - DECODE NO SIGNATURE - - - - - - - -");
        String jwt = "eyJhbGciOiJub25lIn0.eyJpc3N1ZXIiOiJMb3JlbnpvIFBhbmV0dGEiLCJpYXQiOjE1OTI0OTM1OTB9.";
        Jwt decoded = JWT.decode(jwt);
        System.out.println(
                "HEADER: \t" + decoded.getHeader() +
                        "\nBODY: \t\t" + decoded.getBody());
    }
}