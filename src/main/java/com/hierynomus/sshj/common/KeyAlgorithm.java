package com.hierynomus.sshj.common;

public class KeyAlgorithm {

    public static final String RSA = "RSA";
    public static final String DSA = "DSA";

    /** Elliptic curve signature key algorithm for use with BouncyCastle **/
    public static final String ECDSA = "ECDSA";

    /** General elliptic curve algorithm identifier for use with BouncyCastle **/
    public static final String EC_BC = "EC";

    /** General elliptic curve algorithm identifier for use with the Android Keystore **/
    public static final String EC_KEYSTORE = "EC";
}
