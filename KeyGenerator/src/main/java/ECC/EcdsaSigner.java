package ECC;

import java.io.IOException;
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
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class EcdsaSigner {
    
    private static final String SIGNATURE_ALGORITHM = "SHA384withECDSA";
    
    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    private static PrivateKey getPrivateKey(final String content)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        final Reader rdr = new StringReader(content);
                                                       
        try {
            @SuppressWarnings("resource")
            PemObject pem = new PemReader(rdr).readPemObject();
            return KeyFactory.getInstance("EC", "BC").generatePrivate(new PKCS8EncodedKeySpec(pem.getContent()));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private static String generateSignatureOfPlaintext(String plaintext, PrivateKey privateKey) throws SignatureException,
            UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        final Signature ecdsaSignature = Signature.getInstance(SIGNATURE_ALGORITHM, "BC");
        ecdsaSignature.initSign(privateKey);
        ecdsaSignature.update(plaintext.getBytes("UTF-8"));
        
        final byte[] signatureInBinary = ecdsaSignature.sign();
        final String signatureInBase64 = Base64.getEncoder().encodeToString(signatureInBinary);
        
        System.out.println("\nSignature in Binary is " + new String(signatureInBinary));
        System.out.println("Signature in Base64 is " + signatureInBase64);
        
        return signatureInBase64;
    }

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);

        System.out.print("Enter the path to ECC private key: ");
        final String path = sc.nextLine();
        
        try {
            final String contents = new String(Files.readAllBytes(Paths.get(path)));
            PrivateKey privateKey = getPrivateKey(contents);
            
            if (privateKey != null) {
                System.out.println("OK got your private key");
                System.out.print("Enter url to sign: ");
                final String url = sc.nextLine();
                String signature = generateSignatureOfPlaintext(url, privateKey);
                
                //Throwing exception
                //privateKey.destroy(); //Remove private key from memory as soon as we are done using it.
                
                System.out.println("\nHere is your url with signature appended: ");
                System.out.println(url + "?sig=" + signature);
            } else {
                System.out.println("ERROR unable to parse private key contents");
            }

        } catch (IOException ex) {
            System.out.println("ERROR Invalid path");
        } finally{
            sc.close();
        }
    }
}
