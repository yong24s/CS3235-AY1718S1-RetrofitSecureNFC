import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Scanner;

public class ElGamalSigner {

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

        return new Pair<BigInteger, BigInteger>(r, s);
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

    public static void main(String[] args) {
        // public key
        System.out.println("Please provide PUBLIC KEY....");
        Scanner sc = new Scanner(System.in);

        System.out.print("p: ");
        BigInteger p = sc.nextBigInteger();
        sc.nextLine();
        System.out.print("g: ");
        BigInteger g = sc.nextBigInteger();
        sc.nextLine();

        System.out.println("Please provide PRIVATE KEY....");
        System.out.print("x: ");
        BigInteger x = sc.nextBigInteger();
        sc.nextLine();

        System.out.println("Please provide MESSAGE to sign....");
        System.out.print("m: ");
        String m = sc.nextLine();

        System.out.println("Signing....");
        Pair<BigInteger, BigInteger> rs = sign(m, p, g, x);
        System.out.println("r: " + rs.getFirst());
        System.out.println("s: " + rs.getSecond());
        sc.close();
    }
}
