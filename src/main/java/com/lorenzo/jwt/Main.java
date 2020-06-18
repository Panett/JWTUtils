package com.lorenzo.jwt;

import com.lorenzo.jwt.sha256.JwtSha256;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwt;

import java.security.NoSuchAlgorithmException;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException {

        System.out.println("- - - - - - - - - - ENCODE - - - - - - - - - -");
        Map<String, Object> claims = new HashMap<>();
        String jwt = JwtUtils.encode("Lorenzo Panetta", claims, 1, ChronoUnit.MINUTES);
        System.out.println(jwt);

        System.out.println("\n\n- - - - - - - - ENCODE AND SIGN - - - - - - - -");
        String jws = JwtSha256.encodeAndSign("prova secret", "Lorenzo Panetta", claims, 1, ChronoUnit.MINUTES);
        System.out.println(jws);

        System.out.println("\n\n- - - - - - - - - - DECODE - - - - - - - - - -");
        Jwt<Header, Claims> decodeRes = JwtUtils.decodeIgnoringSignature(jws);
        System.out.println(decodeRes);

        System.out.println("\n\n- - - - - - - - - - VERIFY - - - - - - - - - -");
        Jws<Claims> verifyRes = JwtSha256.verify(jws, "prova secret");
        System.out.println(verifyRes);


    }

}
