package ECC;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Date;
import java.sql.Timestamp;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import java.util.Base64;

public class ecdsa {

    public static void GetTimestamp(String info) {
        System.out.println(info + new Timestamp((new Date()).getTime()));
    }

    public static String GenerateSignature(String plaintext, PrivateKey privateKey) throws SignatureException,
            UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature ecdsaSign = Signature.getInstance("SHA512withECDSA", "BC");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(plaintext.getBytes("UTF-8"));
        byte[] signature = ecdsaSign.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean ValidateSignature(String plaintext, PublicKey publicKey, String signature) throws SignatureException,
            InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature ecdsaVerify = Signature.getInstance("SHA512withECDSA", "BC");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(plaintext.getBytes("UTF-8"));
        
        byte[] byteSig = Base64.getDecoder().decode(signature);
        System.out.println(byteSig.length);
        
        return ecdsaVerify.verify(byteSig);
    }

    public static KeyPair GenerateKeys()
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        // Other named curves can be found in
        // http://www.bouncycastle.org/wiki/display/JA1/Supported+Curves+%28ECDSA+and+ECGOST%29
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("B-571");

        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");

        g.initialize(ecSpec, new SecureRandom());

        return g.generateKeyPair();
    }

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        PrivateKey privateKey = ECDSA_Signer.getPrivateKeyValue(null);
        PublicKey publicKey = ECDSA_Signer.getPublicKeyValue(null);

        System.out.println(privateKey.toString());
        System.out.println(publicKey.toString());

         String plaintext = "http://ccmobilelife.sg/p2186/3q/97h";
        // GetTimestamp("Key Generation started: ");
        // KeyPair keys = GenerateKeys();
        // System.out.println(keys.getPublic().toString());
        // System.out.println(keys.getPrivate().toString());
        // GetTimestamp("Key Generation ended: ");
        //
         GetTimestamp("Signature Generation started: ");
         String signature = GenerateSignature(plaintext, privateKey);
         GetTimestamp("Signature Generation ended: ");
         
         String url = plaintext + "?sig=" + signature;
         System.out.println(url);
         
         System.out.println(url.length());
         GetTimestamp("Validation started: ");
         boolean isValidated = ValidateSignature(plaintext, publicKey, signature);
         System.out.println("Result: " + isValidated);
         GetTimestamp("Validation ended: ");
    }

}
