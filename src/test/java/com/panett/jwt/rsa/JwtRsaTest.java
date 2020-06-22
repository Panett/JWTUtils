package com.panett.jwt.rsa;

import lombok.extern.java.Log;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

@Log
public class JwtRsaTest {

    @Test
    void encode() throws Exception {
        KeyPair keyPair = getKeyPair();
        Map<String, Object> claims = new HashMap<>();
        claims.put("issuer", "Lorenzo Panetta");
        String jws = JwtRsa.encode(keyPair.getPrivate(), claims, 1, ChronoUnit.MINUTES);
        log.info(jws);
    }

    @Test
    void verify() throws Exception {
        KeyPair keyPair = getKeyPair();
        String jws = "eyJhbGciOiJSUzI1NiJ9.eyJpc3N1ZXIiOiJMb3JlbnpvIFBhbmV0dGEiLCJpYXQiOjE1OTI4MTk4MDF9.BE6hUBxlWOghpg5rfHAxlmCJAqa9LcxkuwGMqI40wsVdeHVEJ3q8qgI-6-YlC_b_zyE16hjG02Ay64VcWX637WIXj3PaAWih2o4hH8M0-H1Pnz02sJmI2SyCLHPZWlXHoFgQWGF2xiHZvlLIWOPIo6EUMZm14vy77bFeQjJvZXM7WxE-_YgC4a09EZuoJPwA2gMumepDl7vh_3zEZQ7f7H6buGzFBvS_4IAUkpIRcjgFa2eXiwun9VYpAfesvOTklPiJ4W_0IUIRGkdy0JxNwAqX-pco6H8dIN4w3La2c56QwbMeAiWPdJjYbu96dgdCCBIdHIm-7KmC6Sjg9YmGRP38NRMkLhuzGcQq_tszAhGrrRHnlCWMZGNkywcbXIQ2kba_i28hQE4EHJguvjjfIbETj4MNgfTDH0S_ztMpiNr-2mQ96Gvs3_IQqXxk3Jgqcxsv9UPwZ1026pJiaP87TpyL0rzdrsWXRlQsZuyoU-dBNmpwesm7iQAnae37myYSpqow3f49tJzzHIANmPykXTVyWpM0ucXxgaom1fAvnXRSRlwhtBsPRvFKRY6iakxiZ7eanSumAcgtu-HNTNQ8dlSOQb-uO1-OOb_f6iiD-8SiL4fZlcCezn3BEeXy7-DTLDSzZZL0e7z5kgqBCOSv2vF-npUfCmlRbBNlgw9RLyQ";
        JwtRsa.verify(jws, keyPair.getPublic());
    }



    private KeyPair getKeyPair() throws Exception {
        String path = "C:/Users/loren/Desktop/keyStore.p12";
        String password = "secretpassword";
        String alias = "alias";
        return KeystoreLoader.loadKeypairFromKeystore(path, password, alias);
    }
}
