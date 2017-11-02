package com.retrofit.nfc.retrofitsecurenfc;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by Glen on 29-Oct-17.
 */

public class ElGamalVerifier {

    private static final Pattern domainPattern = Pattern.compile("^(?:(?:http[s]?):\\/)?\\/?(?:[^:\\/\\s]+?\\.)*([^:\\/\\s]+\\.[^:\\/\\s]+)");
    private static final Pattern getRParams = Pattern.compile("r=(.+)&|$");
    private static final Pattern getSParams = Pattern.compile("s=(.+)$");
    private final LinkedHashMap<String, PublicKey> publicKeyMap;


    private String domain = "";
    private String r = "";
    private String s = "";

    ElGamalVerifier(LinkedHashMap<String, PublicKey> publicKeyMap) {
        this.publicKeyMap = publicKeyMap;
    }

    public boolean verify(String url) {
        extractDomainAndParams(url);

        if (domain != "" && r != "" && s != "") {
            PublicKey pk = publicKeyMap.get(domain);

            //This scenario where pk is null should never happen
            //As we need to register all domains we can handle,
            //the domain must have a public key in our hashtable
            if (pk != null) {
                return verify(simpleUrlTrim(url), new BigInteger(r, Character.MAX_RADIX), new BigInteger(s, Character.MAX_RADIX), pk.h, pk.p, pk.g);
            }
        }

        return false;
    }

    //Suppose only we use GET params by adding a ?
    private String simpleUrlTrim(String url) {
        return url.substring(0, url.indexOf("?"));
    }

    private void extractDomainAndParams(String url) {
        Matcher urlM = domainPattern.matcher(url);

        if(urlM.find()) {
            domain = urlM.group(1);

            Matcher m = getRParams.matcher(url);

            if(m.find()) {
                r = m.group(1);
            }

            m = getSParams.matcher(url);

            if(m.find()) {
                s = m.group(1);
            }
        }
    }

    private boolean verify(String m, BigInteger r, BigInteger s, BigInteger y, BigInteger p, BigInteger g) {

        // 0 < r < p
        // 0 < s < p-1
        //Ensure inputs are in correct range before we verify or else we can skip this
        if (r.compareTo(BigInteger.ZERO) == 1 && p.compareTo(r) == 1 && s.compareTo(BigInteger.ZERO) == 1
                && p.subtract(BigInteger.ONE).compareTo(s) == 1) {
            BigInteger rhs = (y.modPow(r, p)).multiply(r.modPow(s, p));
            rhs = rhs.mod(p);
            BigInteger hOfM = new BigInteger(SHA256(m));
            BigInteger lhs = g.modPow(hOfM, p);
            return lhs.equals(rhs);
        }

        return false;
    }

    private static byte[] SHA256(String str) {

        try {
            MessageDigest digest;
            digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(str.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }
}
