import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * Security of the ElGamal algorithm depends on the difficulty of computing
 * discrete logs in a large prime modulus
 *
 * - Theorem 1 : a in [Z/Z[p]] then a^(p-1) [p] = 1 - Theorem 2 : the order of
 * an element split the order group
 */

/*
 * Source and Credits to
 * https://raw.githubusercontent.com/Ananasr/Cryptology/master/Crypto/src/main/
 * elgamal/Elgamal.java
 * 
 * Implmented Signature
 * :https://en.wikipedia.org/wiki/ElGamal_signature_scheme#Key_generation
 */
public final class ElGamal { // TODO extends Cryptosystem

    public static BigInteger TWO = new BigInteger("2");

    /**
     * Generate the public key and the secret key for the ElGamal encryption.
     *
     * @param n
     *            key size
     */
    public static List<List<BigInteger>> KeyGen(int n) {
        // (a) take a random prime p with getPrime() function. p = 2 * p' + 1
        // with prime(p') = true
        BigInteger p = getPrime(n, 40, new Random());
        // (b) take a random element in [Z/Z[p]]* (p' order)
        BigInteger g = randNum(p, new Random());
        BigInteger pPrime = p.subtract(BigInteger.ONE).divide(ElGamal.TWO);

        while (!g.modPow(pPrime, p).equals(BigInteger.ONE)) {
            if (g.modPow(pPrime.multiply(ElGamal.TWO), p).equals(BigInteger.ONE))
                g = g.modPow(TWO, p);
            else
                g = randNum(p, new Random());
        }

        // (c) take x random in [0, p' - 1]
        BigInteger x = randNum(pPrime.subtract(BigInteger.ONE), new Random());
        BigInteger h = g.modPow(x, p);
        // secret key is (p, x) and public key is (p, g, h)
        List<BigInteger> sk = new ArrayList<BigInteger>(Arrays.asList(p, x));
        List<BigInteger> pk = new ArrayList<BigInteger>(Arrays.asList(p, g, h));
        // [0] = pk, [1] = sk
        return new ArrayList<List<BigInteger>>(Arrays.asList(pk, sk));
    }

    /**
     * Encrypt ElGamal
     *
     * @param (p,g,h)
     *            public key
     * @param message
     *            message
     */
    public static List<BigInteger> Encrypt(BigInteger p, BigInteger g, BigInteger h, BigInteger message) {
        BigInteger pPrime = p.subtract(BigInteger.ONE).divide(ElGamal.TWO);
        // TODO [0, N -1] or [1, N-1] ?
        BigInteger r = randNum(pPrime, new Random());
        // encrypt couple (g^r, m * h^r)
        return new ArrayList<BigInteger>(Arrays.asList(g.modPow(r, p), message.multiply(h.modPow(r, p))));
    }

    /**
     * Encrypt ElGamal homomorphe
     *
     * @param (p,g,h)
     *            public key
     * @param message
     *            message
     */
    public static List<BigInteger> Encrypt_Homomorph(BigInteger p, BigInteger g, BigInteger h, BigInteger message) {
        BigInteger pPrime = p.subtract(BigInteger.ONE).divide(ElGamal.TWO);
        // TODO [0, N -1] or [1, N-1] ?
        BigInteger r = randNum(pPrime, new Random());
        // encrypt couple (g^r, h^r * g^m)
        BigInteger hr = h.modPow(r, p);
        BigInteger gm = g.modPow(message, p);
        return new ArrayList<BigInteger>(Arrays.asList(g.modPow(r, p), hr.multiply(gm)));
    }

    /**
     * Decrypt ElGamal
     *
     * @param (p,x)
     *            secret key
     * @param (gr,mhr)
     *            (g^r, m * h^r)
     * @return the decrypted message
     */
    public static BigInteger Decrypt(BigInteger p, BigInteger x, BigInteger gr, BigInteger mhr) {
        BigInteger hr = gr.modPow(x, p);
        return mhr.multiply(hr.modInverse(p)).mod(p);
    }

    /**
     * Decrypt ElGamal homomorphe Remarque : il faudra quand même faire une
     * recherche exhaustive de log discret (g^m)
     * 
     * @param (p,x)
     *            secret key
     * @param (gr,mhr)
     *            (g^r, h^r * g^m)
     * @return the decrypted message
     */
    public static BigInteger Decrypt_homomorphe(BigInteger p, BigInteger x, BigInteger g, BigInteger gr,
            BigInteger hrgm) {
        BigInteger hr = gr.modPow(x, p);
        BigInteger gm = hrgm.multiply(hr.modInverse(p)).mod(p);

        BigInteger m = BigInteger.ONE;
        BigInteger gm_prime = g.modPow(m, p);

        while (!gm_prime.equals(gm)) {
            m = m.add(BigInteger.ONE);
            gm_prime = g.modPow(m, p);
        }

        return m;
    }

    /**
     * Return a prime p = 2 * p' + 1
     *
     * @param nb_bits
     *            is the prime representation
     * @param certainty
     *            probability to find a prime integer
     * @param prg
     *            random
     * @return p
     */
    public static BigInteger getPrime(int nb_bits, int certainty, Random prg) {
        BigInteger pPrime = new BigInteger(nb_bits, certainty, prg);
        // p = 2 * pPrime + 1
        BigInteger p = pPrime.multiply(TWO).add(BigInteger.ONE);

        while (!p.isProbablePrime(certainty)) {
            pPrime = new BigInteger(nb_bits, certainty, prg);
            p = pPrime.multiply(TWO).add(BigInteger.ONE);
        }
        return p;
    }

    /**
     * Return a random integer in [0, N - 1]
     *
     * @param N
     * @param prg
     * @return
     */
    public static BigInteger randNum(BigInteger N, Random prg) {
        return new BigInteger(N.bitLength() + 100, prg).mod(N);
    }

    public static Pair<BigInteger, BigInteger> sign(String m, BigInteger p, BigInteger g, BigInteger x) {
        // Choose a random k such that 1 < k < p − 1 and gcd(k, p − 1) = 1
        Random rand = new SecureRandom();

        BigInteger p_minus_1 = p.subtract(BigInteger.ONE);
        int nlen = p_minus_1.bitLength();

        BigInteger k = BigInteger.ZERO;
        BigInteger r = BigInteger.ZERO;
        BigInteger s = BigInteger.ZERO;
        
        do {
            do {
                k = new BigInteger(nlen, rand);
            } while (!k.gcd(p_minus_1).equals(BigInteger.ONE));

            // Compute r === g^k (mod p)
            r = g.modPow(k, p);

            // Compute s === (H(m) - xr)k^-1 (mod p - 1)
            BigInteger hOfM = new BigInteger(SHA256(m));
            BigInteger xr = x.multiply(r);
            // H(m) - xr
            BigInteger HOfM_minus_xr = hOfM.subtract(xr);
            
            s = HOfM_minus_xr.multiply(k.modInverse(p_minus_1));
            s = s.mod(p_minus_1);
            
        } while (s.equals(BigInteger.ZERO));
        
        System.out.println(r);
        System.out.println(s);

        return new Pair<BigInteger, BigInteger>(r, s);
    }
    
    public static boolean verify(String m, BigInteger r, BigInteger s, BigInteger y, BigInteger p, BigInteger g) {
        
        // 0 < r < p
        // 0 < s < p-1
        if (r.compareTo(BigInteger.ZERO) == 1 && p.compareTo(r) == 1 && s.compareTo(BigInteger.ZERO) == 1  && p.subtract(BigInteger.ONE).compareTo(s) == 1 ){
            System.out.println("Verifiable");
        }
        
        
        BigInteger rhs = (y.modPow(r, p)).multiply(r.modPow(s, p));
        rhs = rhs.mod(p);
        System.out.println(rhs);
        BigInteger hOfM = new BigInteger(SHA256(m));
        BigInteger lhs = g.modPow(hOfM, p);
        System.out.println(lhs);
        return lhs.equals(rhs);
    }

    public static byte[] SHA256(String str) {

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

    private static String bytesToHex(byte[] hash) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if (hex.length() == 1)
                hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static void main(String[] args) {
        List<List<BigInteger>> pksk = ElGamal.KeyGen(512);
        // public key
        BigInteger p = pksk.get(0).get(0);
        BigInteger g = pksk.get(0).get(1);
        BigInteger h = pksk.get(0).get(2);
        // secret key
        BigInteger p_sk = pksk.get(1).get(0);
        BigInteger x = pksk.get(1).get(1);
        // System.out.println("Message : 12");
        // List<BigInteger> encrypt = ElGamal.Encrypt_Homomorph(p, g, h, new
        // BigInteger("12"));
        // System.out.println("Decrypted : " + ElGamal.Decrypt_homomorphe(p_sk,
        // x, g, encrypt.get(0), encrypt.get(1)));

        String m = "http://www.google.com/";
        
        Pair<BigInteger, BigInteger> rs = sign(m, p, g, x);
        
        BigInteger r = rs.getFirst();
        BigInteger s = rs.getSecond();
        
        System.out.println(verify(m, r, s, h, p, g));
    }
}