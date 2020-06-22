package com.panett.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwt;
import lombok.extern.java.Log;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Log
class JWSTest {

    @Test
    void encodeHS256() {
        log.info("\n\n- - - - - - - - ENCODE HS256 - - - - - - - -");
        Map<String, Object> claims = new HashMap<>();
        claims.put("issuer", "Lorenzo Panetta");
        String jws = JWS.encode("prova secret", claims, 1, ChronoUnit.MINUTES);
        log.info(jws);
    }

    @Test
    void encodeRS256() throws Exception {
        log.info("\n\n- - - - - - - - ENCODE RS256 - - - - - - - -");
        KeyPair keyPair = getKeyPair();
        Map<String, Object> claims = new HashMap<>();
        claims.put("issuer", "Lorenzo Panetta");
        String jws = JWS.encode(keyPair.getPrivate(), claims, 1, ChronoUnit.MINUTES);
        log.info(jws);
    }

    @Test
    void verifyHS256() {
        log.info("\n\n- - - - - - - - - - VERIFY HS256 - - - - - - - - - -");
        String jws = "eyJhbGciOiJIUzI1NiJ9.eyJpc3N1ZXIiOiJMb3JlbnpvIFBhbmV0dGEiLCJpYXQiOjE1OTI0OTM1MTF9.t7DSyFXkr_-ib" +
                "qKyyoneQW_ongIaRe2RwWmBkVfQDFM";
        Jws<Claims> verifiedJws = JWS.verify(jws, "prova secret");
        log.info("HEADER: \t" + verifiedJws.getHeader() +
                "\nBODY: \t\t" + verifiedJws.getBody() +
                "\nSIGNATURE: \t" + verifiedJws.getSignature());
    }

    @Test
    void verifyRS256() throws Exception {
        log.info("\n\n- - - - - - - - - - VERIFY RS256 - - - - - - - - - -");
        String jwsRS256NoExp = "eyJhbGciOiJSUzI1NiJ9.eyJpc3N1ZXIiOiJMb3JlbnpvIFBhbmV0dGEiLCJpYXQiOjE1OTI4MzUxNzZ9.q0x" +
                "R4vF-uF4vriSgR5tU3gU_t9HTwN-5P8C_FSgni3qQU8cmGMnY9qv3XryS40IMD15kLjYsnZ4C466OQuhwPsmPr2dQoDTQ7ulC66P" +
                "WKTGoP_lRu2STRJFnuFmz7-gdeM8BCwYI7hvc0GPhsa6f320mydkYT8gTERT2c06dbg7sWWlqQWW6Cy8LfDY4w11pYfKVBmqKRdM" +
                "V1dHCFwrPOCkFoppdTQvzu_pFNRxLHeGS-KJ0KwrvrHWkuKISgUE2c_vb52MoBDDCbBYU7pCA0wE-mzDZ1QI9ef-8FJYIK2pZEAq" +
                "qkxNzL2rRwDQT1rlpQN9X6PQsr6tAnkh-fe3pTgvVKpCrz63NDQQlfNKFPU_SaxcGLh7TbdEueN9xaAfh1gt7b7zsLYls7TVmp9_" +
                "Wk2AUEc4JXLg870Tn1yjt9XD40pQEFiqAF3jFFTIRFOuY_jBRawNXFckNFq59g2iFjephHQbF3Y5_Yj01a_SJqdPNX3Cs-UYYBMZ" +
                "qQQ8yzKnk_PAuXgVnYF_LcxtvUgrGdCKC_KuuyoWFPrVsrmlkpw74rocAdH0Fh5hHTZIcXohFKdBTrqk5BQEjVqpjGjXLpv7_R71" +
                "dBpWqHVOJsAZKhWco3ateGwUma7jln3weXwVJ5t3lVXroF5pv5AcROf5_Q_GE_-DQVdnD2mDWLTauCVE";
        KeyPair keyPair = getKeyPair();
        Jws<Claims> verifiedJws = JWS.verify(jwsRS256NoExp, keyPair.getPublic());
        log.info("HEADER: \t" + verifiedJws.getHeader() +
                "\nBODY: \t\t" + verifiedJws.getBody() +
                "\nSIGNATURE: \t" + verifiedJws.getSignature());
    }

    @Test
    void decodeIgnoringExpiration() {
        String jwsHS256 = "eyJhbGciOiJIUzI1NiJ9.eyJpc3N1ZXIiOiJMb3JlbnpvIFBhbmV0dGEiLCJpYXQiOjE1OTI4MzQ4MDEsImV4cCI6M" +
                "TU5MjgzNDg2MX0.yHoUCOe9CBjtRNSFVXLSPrWwSfd390ic8S5oz5XTasY";
        Map<String, String> decoded = JWS.decodeIgnoringExpiration(jwsHS256);
        log.info(decoded.toString());
    }

    private KeyPair getKeyPair() throws Exception {
        String path = "C:/Users/loren/Desktop/keyStore.p12";
        String password = "secretpassword";
        String alias = "alias";
        return KeystoreLoader.loadKeypairFromKeystore(path, password, alias);
    }
}