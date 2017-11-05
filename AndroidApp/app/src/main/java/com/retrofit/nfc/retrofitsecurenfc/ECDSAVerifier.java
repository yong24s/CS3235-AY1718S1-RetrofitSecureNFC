package com.retrofit.nfc.retrofitsecurenfc;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemReader;

import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import android.util.Base64;

/**
 * Created by Glen on 06-Nov-17.
 */

public class ECDSAVerifier {
    public static boolean ValidateSignature(String plaintext, PublicKey publicKey, String signature) throws SignatureException,
            InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        Signature ecdsaVerify = Signature.getInstance("SHA384withECDSA", "BC");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(plaintext.getBytes("UTF-8"));

        byte[] byteSig = Base64.decode(signature, Base64.DEFAULT);
        System.out.println(byteSig.length);

        return false;
    }

    public static PublicKey getPublicKeyValue(byte[] x509key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Security.addProvider(new BouncyCastleProvider());
        Reader rdr = new StringReader("-----BEGIN PUBLIC KEY-----\n"
                +"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEww2MbZ2l0AziUHfbRmjyiXd/rdmG\n"
                +"l3E22HX644ipw7+7GNlkRas8Eu7iEbCipSVE492TbvBtlH9equJkHKMcjw==\n"
                +"-----END PUBLIC KEY-----\n"); // or from file etc.

        try {
            PemObject spki;
            spki = new PemReader(rdr).readPemObject();
            return KeyFactory.getInstance("EC","BC").generatePublic(new X509EncodedKeySpec(spki.getContent()));
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }
}
