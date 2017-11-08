package com.retrofit.nfc.retrofitsecurenfc;

import org.apache.commons.io.IOUtils;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import android.content.Context;
import android.content.res.AssetManager;
import android.util.Base64;

/**
 * Created by Glen on 06-Nov-17.
 */

public class ECDSAVerifier {

    private static final Pattern domainPattern = Pattern.compile("https?:\\/\\/(?:www\\.)?([-a-zA-Z0-9@:%._\\+~#=]{2,256}\\.[a-z]{2,6}\\b)*(\\/[\\/\\d\\w\\.-]*)*(?:[\\?])*(.+)*");
    private static final Pattern getSigParams = Pattern.compile("sig=(.+)$");

    private String domain;
    private String sig;

    private Context context;

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    public ECDSAVerifier(Context context) {
        this.context = context;
    }

    //Suppose only we use GET params by adding a ?
    private String simpleUrlTrim(String url) {
        return url.substring(0, url.indexOf("?"));
    }

    private void extractDomainAndParams(String url) {
        Matcher urlM = domainPattern.matcher(url);

        if(urlM.find()) {
            domain = urlM.group(1);

            Matcher m = getSigParams.matcher(url);

            if(m.find()) {
                sig = m.group(1);
            }
        }
    }

    private static boolean isNullOrBlank(String param) {
        return param == null || param.trim().length() == 0;
    }

    public boolean verify(String url) {
        extractDomainAndParams(url);

        if (!isNullOrBlank(domain) && !isNullOrBlank(sig)) {
            PublicKey pk = getPublicKeyValue(readPublicKey(domain));

            //This scenario where pk is null should never happen
            //As we need to register all domains we can handle,
            //the domain must have a public key in our hashtable
            if (pk != null) {
                return ValidateSignature(simpleUrlTrim(url), pk, sig);
            }
        }

        return false;
    }

    public boolean ValidateSignature(String plaintext, PublicKey publicKey, String signature) {
        try {
//            Security.addProvider(new BouncyCastleProvider());
            Signature ecdsaVerify = Signature.getInstance("SHA384withECDSA", "BC");
            ecdsaVerify.initVerify(publicKey);
            ecdsaVerify.update(plaintext.getBytes("UTF-8"));
            byte[] byteSig = Base64.decode(signature, Base64.DEFAULT);
            return ecdsaVerify.verify(byteSig);
        } catch (Exception ex) {

        }

        return false;
    }

    private String readPublicKey(String domainAsFileName) {

        try {
//            InputStream is = context.getResources().openRawResource()
            AssetManager am = context.getAssets();
            InputStream is = am.open("certs/" + domainAsFileName);
            String s = IOUtils.toString(is);
            IOUtils.closeQuietly(is);

            return s;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static PublicKey getPublicKeyValue(String publicKeyContent) {
        if (publicKeyContent == null) {
            return null;
        }

//        Security.addProvider(new BouncyCastleProvider());
//        Reader rdr = new StringReader(publicKeyContent);

        try {
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            InputStream is = new ByteArrayInputStream(publicKeyContent.getBytes());
            X509Certificate cecerr = (X509Certificate) fact.generateCertificate(is);
            PublicKey key = cecerr.getPublicKey();
            return key;
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }
}
