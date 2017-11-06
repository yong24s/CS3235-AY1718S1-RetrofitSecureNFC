package ECC;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
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
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
        Reader rdr = new StringReader("-----BEGIN PRIVATE KEY-----\n" +
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvVDmildtbRaYT4S2\n" +
                "N9ZG9M8zDHUZNrtvUBA8X8HP0r6hRANCAASgkUnH4WTKOt+TMwddEeyHpHgQ8PuX\n" +
                "GpaP2ol32IwlWeDi+EcmHX56HNcJ8DrkayvuoqfI4W6b6A3TIUuhQy4H\n" +
                "-----END PRIVATE KEY-----"); // or from file etc.

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
//        Reader rdr = new StringReader("-----BEGIN PUBLIC KEY-----\n"
//                +"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEww2MbZ2l0AziUHfbRmjyiXd/rdmG\n"
//                +"l3E22HX644ipw7+7GNlkRas8Eu7iEbCipSVE492TbvBtlH9equJkHKMcjw==\n"
//                +"-----END PUBLIC KEY-----\n"); // or from file etc.

//        Reader rdr = new StringReader("-----BEGIN CERTIFICATE-----\n" + 
//"MIIB2zCCAYGgAwIBAgIJAJ9UWB+CT5q7MAoGCCqGSM49BAMCMEoxCzAJBgNVBAYT\n"+
//"AlNHMQswCQYDVQQIDAJTRzELMAkGA1UEBwwCU0cxITAfBgNVBAoMGEludGVybmV0\n"+
//"IFdpZGdpdHMgUHR5IEx0ZDAeFw0xNzExMDUxNzA4NDlaFw0xODExMDUxNzA4NDla\n"+
//"MEoxCzAJBgNVBAYTAlNHMQswCQYDVQQIDAJTRzELMAkGA1UEBwwCU0cxITAfBgNV\n"+
//"BAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDBZMBMGByqGSM49AgEGCCqGSM49\n"+
//"AwEHA0IABMMNjG2dpdAM4lB320Zo8ol3f63ZhpdxNth1+uOIqcO/uxjZZEWrPBLu\n"+
//"4hGwoqUlROPdk27wbZR/XqriZByjHI+jUDBOMB0GA1UdDgQWBBT6J4jHCuOlkvxd\n"+
//"jSIhQa+638yX0zAfBgNVHSMEGDAWgBT6J4jHCuOlkvxdjSIhQa+638yX0zAMBgNV\n"+
//"HRMEBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIC01ZqikAUV0im38RqW3JE+k6SPq\n"+
//"o+rAiXXWXoGCzRL+AiEA4L3NC0muqSh+MZRXy31AAjh/hmiybjbsG6ZoJJGNSis=\n"+
//"-----END CERTIFICATE-----"); // or from file etc.
        
        String str = ("-----BEGIN CERTIFICATE-----\n" + 
                "MIICWjCCAgGgAwIBAgIJAMsd11jSMscIMAoGCCqGSM49BAMCMIGJMQswCQYDVQQG\n" +
                "EwJTRzESMBAGA1UECAwJU2luZ2Fwb3JlMRIwEAYDVQQHDAlTaW5nYXBvcmUxGDAW\n" +
                "BgNVBAoMD2NjbW9iaWxlbGlmZS5zZzEYMBYGA1UEAwwPY2Ntb2JpbGVsaWZlLnNn\n" +
                "MR4wHAYJKoZIhvcNAQkBFg9jY21vYmlsZWxpZmUuc2cwHhcNMTcxMTA1MjM0MzQ5\n" +
                "WhcNMTgxMTA1MjM0MzQ5WjCBiTELMAkGA1UEBhMCU0cxEjAQBgNVBAgMCVNpbmdh\n" +
                "cG9yZTESMBAGA1UEBwwJU2luZ2Fwb3JlMRgwFgYDVQQKDA9jY21vYmlsZWxpZmUu\n" +
                "c2cxGDAWBgNVBAMMD2NjbW9iaWxlbGlmZS5zZzEeMBwGCSqGSIb3DQEJARYPY2Nt\n" +
                "b2JpbGVsaWZlLnNnMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoJFJx+Fkyjrf\n" +
                "kzMHXRHsh6R4EPD7lxqWj9qJd9iMJVng4vhHJh1+ehzXCfA65Gsr7qKnyOFum+gN\n" +
                "0yFLoUMuB6NQME4wHQYDVR0OBBYEFAclflYeL3EyDxwbEGNgy+7c3KZSMB8GA1Ud\n" +
                "IwQYMBaAFAclflYeL3EyDxwbEGNgy+7c3KZSMAwGA1UdEwQFMAMBAf8wCgYIKoZI\n" +
                "zj0EAwIDRwAwRAIgYuCguzcicmHRPSlNSIU1PEHZilrOZZzUpPqRVbQbwzoCIAdJ\n" +
                "kL+MJoTVT5zkLEZJy3fI2voORsqOHpqGKcBouk3P\n" +
                "-----END CERTIFICATE-----"); 
      
        try {
            
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            InputStream is = new ByteArrayInputStream(str.getBytes());
            X509Certificate cecerr = (X509Certificate) fact.generateCertificate(is);
            PublicKey key = cecerr.getPublicKey();
            return key;
//            org.bouncycastle.util.io.pem.PemObject spki;
//            spki = new org.bouncycastle.util.io.pem.PemReader(rdr).readPemObject();
//            return KeyFactory.getInstance("EC","BC").generatePublic(new X509EncodedKeySpec(spki.getContent()));
//            
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        return null;
    }
}
