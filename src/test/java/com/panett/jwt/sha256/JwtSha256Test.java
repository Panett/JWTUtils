package com.panett.jwt.sha256;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

class JwtSha256Test {

    @Test
    void encodeAndSign() throws NoSuchAlgorithmException {
        System.out.println("\n\n- - - - - - - - ENCODE AND SIGN - - - - - - - -");
        Map<String, Object> claims = new HashMap<>();
        claims.put("issuer", "Lorenzo Panetta");
        String jws = JwtSha256.encodeAndSign("prova secret", claims, 1, ChronoUnit.MINUTES);
        System.out.println(jws);
    }

    @Test
    void verify() throws NoSuchAlgorithmException {
        System.out.println("\n\n- - - - - - - - - - VERIFY - - - - - - - - - -");
        String jws = "eyJhbGciOiJIUzI1NiJ9.eyJpc3N1ZXIiOiJMb3JlbnpvIFBhbmV0dGEiLCJpYXQiOjE1OTI0OTM1MTF9.t7DSyFXkr_-ibqKyyoneQW_ongIaRe2RwWmBkVfQDFM";
        Jws<Claims> verifyRes = JwtSha256.verify(jws, "prova secret");
        System.out.println(
                "HEADER: \t" + verifyRes.getHeader() +
                        "\nBODY: \t\t" + verifyRes.getBody() +
                        "\nSIGNATURE: \t" + verifyRes.getSignature());
    }
}