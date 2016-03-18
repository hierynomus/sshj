package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.common.SecurityUtils;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.custom.djb.Curve25519;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.BitSet;

public class Curve25519DH extends DHBase {


    private byte[] secretKey;

    public Curve25519DH() {
        super("ECDSA", "ECDH");
    }

    @Override
    void computeK(byte[] f) throws GeneralSecurityException {
        byte[] k = new byte[32];
        djb.Curve25519.curve(k, secretKey, f);
        setK(new BigInteger(1, k));
    }

    @Override
    public void init(AlgorithmParameterSpec params) throws GeneralSecurityException {
        SecureRandom secureRandom = new SecureRandom();
        byte[] secretBytes =  new byte[32];
        secureRandom.nextBytes(secretBytes);
        byte[] publicBytes = new byte[32];
        djb.Curve25519.keygen(publicBytes, null, secretBytes);
        this.secretKey = Arrays.copyOf(secretBytes, secretBytes.length);
        setE(publicBytes);
    }

    /**
     * TODO want to figure out why BouncyCastle does not work.
     * @return The initialized curve25519 parameter spec
     */
    public static AlgorithmParameterSpec getCurve25519Params() {
        X9ECParameters ecP = CustomNamedCurves.getByName("curve25519");
        return new ECParameterSpec(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
    }
}
