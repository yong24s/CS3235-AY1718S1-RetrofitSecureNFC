import java.math.BigInteger;
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
 * https://en.wikipedia.org/wiki/ElGamal_signature_scheme#Key_generation
 */
public class ElGamalKeyGenerator {

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
        BigInteger p = getPrime(n, 256, new SecureRandom());
        // (b) take a random element in [Z/Z[p]]* (p' order)
        BigInteger g = randNum(p, new SecureRandom());
        BigInteger pPrime = p.subtract(BigInteger.ONE).divide(ElGamal.TWO);

        while (!g.modPow(pPrime, p).equals(BigInteger.ONE)) {
            if (g.modPow(pPrime.multiply(ElGamal.TWO), p).equals(BigInteger.ONE))
                g = g.modPow(TWO, p);
            else
                g = randNum(p, new SecureRandom());
        }

        // (c) take x random in [0, p' - 1]
        BigInteger x = randNum(pPrime.subtract(BigInteger.ONE), new SecureRandom());
        BigInteger h = g.modPow(x, p);
        // secret key is (p, x) and public key is (p, g, h)
        List<BigInteger> sk = new ArrayList<BigInteger>(Arrays.asList(p, x));
        List<BigInteger> pk = new ArrayList<BigInteger>(Arrays.asList(p, g, h));
        // [0] = pk, [1] = sk
        return new ArrayList<List<BigInteger>>(Arrays.asList(pk, sk));
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

    public static void main(String[] args) {
        final int bits = 224;
        System.out.printf("Generating %d bit keys...\n\n", bits);

        List<List<BigInteger>> pksk = KeyGen(bits);
        // public key
        BigInteger p = pksk.get(0).get(0);
        BigInteger g = pksk.get(0).get(1);
        BigInteger h = pksk.get(0).get(2);
        // secret key
        BigInteger p_sk = pksk.get(1).get(0);
        BigInteger x = pksk.get(1).get(1);

        System.out.println("PUBLIC KEY");
        System.out.println("p: " + p);
        System.out.println("g: " + g);
        System.out.println("h: " + h);

        System.out.println();
        System.out.println();

        System.out.println("PRIVATE KEY");
        System.out.println("p: " + p_sk);
        System.out.println("x: " + x);

    }
}