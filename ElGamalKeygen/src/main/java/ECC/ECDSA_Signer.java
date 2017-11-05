package ECC;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class ECDSA_Signer {
    
    public static PrivateKey getPrivateKeyValue(byte[] pkcs8key) throws NoSuchAlgorithmException, InvalidKeySpecException {
    
//        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8key);
//        KeyFactory factory = KeyFactory.getInstance("ECDSA");
//        PrivateKey privateKey = factory.generatePrivate(spec);
        
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Reader rdr = new StringReader("-----BEGIN PRIVATE KEY-----\n"
                +"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQglm42vhKLVyCh1Vi6\n"
                +"Bio04jbv7FNf4ar3+MGWPI1748GhRANCAATDDYxtnaXQDOJQd9tGaPKJd3+t2YaX\n"
                +"cTbYdfrjiKnDv7sY2WRFqzwS7uIRsKKlJUTj3ZNu8G2Uf16q4mQcoxyP\n"
                +"-----END PRIVATE KEY-----"); // or from file etc.

        try {
            org.bouncycastle.util.io.pem.PemObject spki;
            spki = new org.bouncycastle.util.io.pem.PemReader(rdr).readPemObject();
            return KeyFactory.getInstance("EC","BC").generatePrivate(new PKCS8EncodedKeySpec(spki.getContent()));
            
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        
        return null;
    }
    
    public static PublicKey getPublicKeyValue(byte[] x509key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        
//        X509EncodedKeySpec spec = new X509EncodedKeySpec(x509key);
//        KeyFactory factory = KeyFactory.getInstance("ECDSA");
//        PublicKey publicKey = factory.generatePublic(spec);
//
//        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("prime256v1");
//        KeyFactory kf = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
//        ECNamedCurveSpec params = new ECNamedCurveSpec("prime256v1", spec.getCurve(), spec.getG(), spec.getN());
//        ECPoint point =  ECPointUtil.decodePoint(params.getCurve(), x509key);
//        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
//        ECPublicKey pk = (ECPublicKey) kf.generatePublic(pubKeySpec);
//        
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Reader rdr = new StringReader("-----BEGIN PUBLIC KEY-----\n"
                +"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEww2MbZ2l0AziUHfbRmjyiXd/rdmG\n"
                +"l3E22HX644ipw7+7GNlkRas8Eu7iEbCipSVE492TbvBtlH9equJkHKMcjw==\n"
                +"-----END PUBLIC KEY-----\n"); // or from file etc.

       
        try {
            org.bouncycastle.util.io.pem.PemObject spki;
            spki = new org.bouncycastle.util.io.pem.PemReader(rdr).readPemObject();
            return KeyFactory.getInstance("EC","BC").generatePublic(new X509EncodedKeySpec(spki.getContent()));
            
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        return null;
    }
}
