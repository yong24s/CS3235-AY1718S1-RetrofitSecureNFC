package ECC;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ecdsaVerifier {

    public static PublicKey getPublicKeyValue(final String content)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        try {
            // For reading public key rather than cert
            // org.bouncycastle.util.io.pem.PemObject spki;
            // spki = new
            // org.bouncycastle.util.io.pem.PemReader(rdr).readPemObject();
            // return KeyFactory.getInstance("EC","BC").generatePublic(new
            // X509EncodedKeySpec(spki.getContent()));
            //

            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            InputStream is = new ByteArrayInputStream(content.getBytes());
            X509Certificate cert = (X509Certificate) fact.generateCertificate(is);
            PublicKey key = cert.getPublicKey();
            return key;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static boolean ValidateSignature(String plaintext, PublicKey publicKey, String signature)
            throws SignatureException, InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException,
            NoSuchProviderException {
        Signature ecdsaVerify = Signature.getInstance("SHA384withECDSA", "BC");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(plaintext.getBytes("UTF-8"));

        byte[] byteSig = Base64.getDecoder().decode(signature);
        
        return ecdsaVerify.verify(byteSig);
    }

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        Scanner sc = new Scanner(System.in);

        // public key
        System.out.print("Enter the path to your ECC public key: ");
        final String path = sc.nextLine();

        try {
            String contents = new String(Files.readAllBytes(Paths.get(path)));
            PublicKey publicKey = getPublicKeyValue(contents);

            if (publicKey != null) {
                System.out.println("OK got your public key contents");
                System.out.print("Enter url to validate: ");
                final String url_all = sc.nextLine();
                
                final int index = url_all.indexOf("?sig=");
                
                if (index != -1) {
                    final String url = url_all.substring(0, index);
                    final String sig = url_all.substring(index).replace("?sig=", "");
                    
                    System.out.println("VERIFIED: " + ValidateSignature(url, publicKey, sig));                    
                } else {
                    System.out.println("ERROR url has no signature");
                }
            } else {
                System.out.println("ERROR unable to parse public key contents");
            }

        } catch (Exception ex) {
            System.out.println("ERROR Invalid path");
            ex.printStackTrace();
        } finally {
            sc.close();
        }
    }
}
