package com.retrofit.nfc.retrofitsecurenfc;

import org.apache.commons.io.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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

    private Context context;
    private String domain;
    private String sig;

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    public ECDSAVerifier(Context context) {
        this.context = context;
    }

    //Simple assumption: Signature is the first parameter in GET, so we use ? to find it
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
            final PublicKey pk = getPublicKey(readPublicKey(domain));

            if (pk != null) {
                return validateSignature(simpleUrlTrim(url), pk, sig);
            }
        }

        return false;
    }

    private final boolean validateSignature(String plaintext, PublicKey publicKey, String signature) {
        try {
            final Signature ecdsaVerify = Signature.getInstance("SHA384withECDSA", "BC");
            ecdsaVerify.initVerify(publicKey);
            ecdsaVerify.update(plaintext.getBytes("UTF-8"));
            final byte[] byteSig = Base64.decode(signature, Base64.DEFAULT);
            return ecdsaVerify.verify(byteSig);
        } catch (Exception ex) {

        }

        return false;
    }

    private final String readPublicKey(String domainAsFileName) {

        try {
            AssetManager am = context.getAssets();
            InputStream is = am.open("certs/" + domainAsFileName);
            final String str = IOUtils.toString(is);
            IOUtils.closeQuietly(is);
            return str;
        } catch (IOException e) {

        }

        return null;
    }

    private final PublicKey getPublicKey(String publicKeyContent) {
        if (publicKeyContent == null) {
            return null;
        }

        try {
            final CertificateFactory fact = CertificateFactory.getInstance("X.509");
            final InputStream is = new ByteArrayInputStream(publicKeyContent.getBytes());
            final X509Certificate cecerr = (X509Certificate) fact.generateCertificate(is);
            final PublicKey key = cecerr.getPublicKey();
            return key;
        } catch (Exception e) {
        }

        return null;
    }
}
