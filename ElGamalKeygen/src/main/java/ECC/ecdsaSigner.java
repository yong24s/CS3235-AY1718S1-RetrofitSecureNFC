package ECC;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
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
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

public class ecdsaSigner {

    public static PrivateKey getPrivateKeyValue(final String content)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        Reader rdr = new StringReader(content);
                                                       
        try {
            org.bouncycastle.util.io.pem.PemObject spki;
            spki = new org.bouncycastle.util.io.pem.PemReader(rdr).readPemObject();
            return KeyFactory.getInstance("EC", "BC").generatePrivate(new PKCS8EncodedKeySpec(spki.getContent()));

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static String GenerateSignature(String plaintext, PrivateKey privateKey) throws SignatureException,
            UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature ecdsaSign = Signature.getInstance("SHA384withECDSA", "BC");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(plaintext.getBytes("UTF-8"));
        byte[] signature_binary = ecdsaSign.sign();
        String signature_base64 = Base64.getEncoder().encodeToString(signature_binary);
        System.out.println("\nSignature in Binary is " + new String(signature_binary));
        System.out.println("Signature in Base64 is " + signature_base64);
        
        return signature_base64;
    }

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        Scanner sc = new Scanner(System.in);

        // public key
        System.out.print("Enter the path to your ECC private key: ");
        final String path = sc.nextLine();
        
        try {
            String contents = new String(Files.readAllBytes(Paths.get(path)));
            PrivateKey privateKey = getPrivateKeyValue(contents);
            
            if (privateKey != null) {
                System.out.println("OK got your private key contents");
                System.out.print("Enter url to sign: ");
                final String url = sc.nextLine();
                String signature = GenerateSignature(url, privateKey);
                
                System.out.println("\nHere is your url with signature appended: ");
                System.out.println(url + "?sig=" + signature);
            } else {
                System.out.println("ERROR unable to parse private key contents");
            }

        } catch (Exception ex) {
            System.out.println("ERROR Invalid path");
        } finally{
            sc.close();
        }
    }
}
