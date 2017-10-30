import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class ElGamalVerifier {
    public static boolean verify(String m, BigInteger r, BigInteger s, BigInteger y, BigInteger p, BigInteger g) {

        // 0 < r < p
        // 0 < s < p-1
        if (r.compareTo(BigInteger.ZERO) == 1 && p.compareTo(r) == 1 && s.compareTo(BigInteger.ZERO) == 1
                && p.subtract(BigInteger.ONE).compareTo(s) == 1) {
            System.out.println("Inputs are in correct range");
        }

        BigInteger rhs = (y.modPow(r, p)).multiply(r.modPow(s, p));
        rhs = rhs.mod(p);
        BigInteger hOfM = new BigInteger(SHA384(m));
        BigInteger lhs = g.modPow(hOfM, p);
        return lhs.equals(rhs);
    }

    public static byte[] SHA384(String str) {

        try {
            MessageDigest digest;
            digest = MessageDigest.getInstance("SHA-384");
            return digest.digest(str.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }

    public static void main(String[] args) {
        System.out.println("Please provide PUBLIC KEY....");
        Scanner sc = new Scanner(System.in);

        System.out.print("p: ");
        BigInteger p = sc.nextBigInteger();
        sc.nextLine();
        System.out.print("g: ");
        BigInteger g = sc.nextBigInteger();
        sc.nextLine();
        System.out.print("h: ");
        BigInteger h = sc.nextBigInteger();
        sc.nextLine();

        System.out.println("Please provide SIGNATURE....");
        System.out.print("r: ");
        BigInteger r = sc.nextBigInteger();
        sc.nextLine();
        
        System.out.print("s: ");
        BigInteger s = sc.nextBigInteger();
        sc.nextLine();
        
        System.out.println("Please provide MESSAGE....");
        System.out.print("m: ");
        String m = sc.nextLine();

        System.out.println("Verifiable: " + verify(m, r, s, h, p, g));
        
        System.out.println("Compressing....");
        
        
//        BigInteger(String val, int radix)
        
        String compressed = String.format("%s?r=%s&s=%s", m, r.toString(Character.MAX_RADIX), s.toString(Character.MAX_RADIX));
        System.out.println(compressed);
        
        try {
            byte[] utf8Bytes = compressed.getBytes("UTF-8");
            System.out.println("Payload size: " + (utf8Bytes.length - 2) + " bytes"); //-2  as http:// not in actual payload.
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
