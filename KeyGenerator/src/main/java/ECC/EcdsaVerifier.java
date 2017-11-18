package ECC;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Scanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EcdsaVerifier {
    
    private static final String SIGNATURE_ALGORITHM = "SHA384withECDSA";
    
    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }
    
    private static final PublicKey getPublicKey(final String content)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        try {
             //Use the following for reading ec public key
             /*
                 org.bouncycastle.util.io.pem.PemObject spki;
                 spki = new
                 org.bouncycastle.util.io.pem.PemReader(rdr).readPemObject();
                 return KeyFactory.getInstance("EC","BC").generatePublic(new
                 X509EncodedKeySpec(spki.getContent()));
             */
            
            //Use the following for reading X509 public certificate 
            final CertificateFactory factory = CertificateFactory.getInstance("X.509");
            final InputStream is = new ByteArrayInputStream(content.getBytes());
            final X509Certificate cert = (X509Certificate) factory.generateCertificate(is);
            final PublicKey key = cert.getPublicKey();
            return key;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private static boolean validateSignature(String plaintext, PublicKey publicKey, String signatureInBase64)
            throws SignatureException, InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException,
            NoSuchProviderException {
        
        final Signature ecdsaVerify = Signature.getInstance(SIGNATURE_ALGORITHM, "BC");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(plaintext.getBytes("UTF-8"));

        final byte[] signatureInBinary = Base64.getDecoder().decode(signatureInBase64);
        
        return ecdsaVerify.verify(signatureInBinary);
    }

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);

        System.out.print("Enter the path to ECC public certificate: ");
        final String path = sc.nextLine();

        try {
            final String contents = new String(Files.readAllBytes(Paths.get(path)));
            final PublicKey publicKey = getPublicKey(contents);

            if (publicKey != null) {
                System.out.println("OK got your public key contents");
                System.out.print("Enter url to validate: ");
                
                final String inputUrl = sc.nextLine();                
                final int indexOfSig = inputUrl.indexOf("?sig=");
                
                if (indexOfSig != -1) {
                    final String url = inputUrl.substring(0, indexOfSig);
                    final String signatureInBase64 = inputUrl.substring(indexOfSig).replace("?sig=", "");
                    
                    System.out.println("VERIFIED: " + validateSignature(url, publicKey, signatureInBase64));                    
                } else {
                    System.out.println("ERROR url has no signature");
                }
            } else {
                System.out.println("ERROR unable to parse public key contents");
            }

        } catch (IOException ex) {
            System.out.println("ERROR Invalid path");
        } finally {
            sc.close();
        }
    }
}
