package com.panett.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

class JWETest {

    @Test
    void encrypt() throws Exception {
        String jws = "eyJhbGciOiJIUzI1NiJ9.eyJpc3N1ZXIiOiJMb3JlbnpvIFBhbmV0dGEiLCJpYXQiOjE1OTI0OTM1MTF9.t7DSyFXkr_-ib" +
                "qKyyoneQW_ongIaRe2RwWmBkVfQDFM";
        JWE jweHelper = new JWE(getKeyPair());
        String encrypted = jweHelper.encrypt(jws);
        System.out.println("ENCRYPTED: \n" + encrypted);

    }

    @Test
    void decrypt() throws Exception {
        String jwe = "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.Bxhj0tgM1PpCZE3Nw2CJ97eeA49jYfe6sm8seiogtSM9RNhcg8JEHJC2lKDjhoENk7FahdI-O3CMIYSbgm3vasp_kqMZsX-JmziarL3SXrVCY9aSj4TM3CCbGbGG5irJoB5oxCGqwcGQhrouEVhxaOsec-pgZRAMjtbptVdfnHJh7mO1Df7UFQWGxZW6ft4QXg-naArVXT2PUaq_wpzRWm7GuwMcMw17z8MjrCaDgWCxMaHU16EA-vDDLovvc437uzez7UIAjslK_Ujt2Efxv1kIn7hMIh6NIhZFxzlQjZbZ1WG9kVGymb9UjPohPDDJ5g-SYnWj0bOlG2lHRAU9pySwKMYwSPpnO-nJcVMVUiV_L2FCL48FASHyGQFXIv9fBpkJA6tZqAQ91s9m3Hxd9CyjTpkdCMgdKinAkCJEE--6EGpsarNsnTCsLNAVqO5SLroJFz_vDhywR2JY-FUHnnUQ4qMgdlVZSuZ68YJyCaKrIHjsY_SNIqtpKfp5KrNGwBaJfPhn_Y1UowTh-conGXYDjjSwBEtw96VOvpXnlRsir1eUqUxWEGpJSQKq2tYZfxOavet1WqiKZ5TfvQ4_l7L1ktZNMNaIx70CStnNGRsyLUjNEsGn2PC13EuHI_GTXnsiyj9LUrue5R4vDa8OC0nfN3yCJ2Z8Wrcz97kOymc.TXmVZsAK7tBHWPTy.a6dezzAOzKrSd6VW9bvoECQCBQV-KPX5o6lbWYcZ7oTtKnW-VjhRYeq-xq-DFtICLSKXsHCkRzspUvjQWdmBPZbkLn7GjTiPiWsvCvH9dPvRtxI_ypFVXi06Oa3roqtou-Mx9Gphxn-b4JCcDyPDUCF7GxH8EseAtS6uKVg.sFVqY3pLlXfSK5a7kSXfnA";
        JWE jweHelper = new JWE(getKeyPair());
        String decrypted = jweHelper.decrypt(jwe);
        System.out.println("DECRYPTED: \n" + decrypted);
        verify(decrypted);
    }


    void verify(String jws) {
        Jws<Claims> verifiedJws = JWS.verify(jws, "prova secret");
        System.out.println("HEADER: \t" + verifiedJws.getHeader() +
                "\nBODY: \t\t" + verifiedJws.getBody() +
                "\nSIGNATURE: \t" + verifiedJws.getSignature());
    }

    private KeyPair getKeyPair() throws Exception {
        String path = "/home/lorenzo/Desktop/key-pair/JWS/keyStore.p12";
        //String path = "C:/Users/loren/Desktop/keyStore.p12";
        String password = "secretpassword";
        String alias = "alias";
        return KeystoreLoader.loadKeypairFromKeystore(path, password, alias);
    }
}