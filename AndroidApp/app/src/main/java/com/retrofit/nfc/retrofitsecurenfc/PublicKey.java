package com.retrofit.nfc.retrofitsecurenfc;

import java.math.BigInteger;

/**
 * Created by Glen on 29-Oct-17.
 */

public class PublicKey {

    public final BigInteger p;
    public final BigInteger g;
    public final BigInteger h;

    public PublicKey(String str) {
        String[] values = str.split(",");

        p = new BigInteger(values[0].trim());
        g = new BigInteger(values[1].trim());
        h = new BigInteger(values[2].trim());
    }
}
