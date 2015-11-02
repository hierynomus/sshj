package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.common.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;

public class ECDH extends DHBase {

    private ECParameterSpec ecParameterSpec;

    public ECDH() {
        super("EC", "ECDH");
    }

    protected void init(AlgorithmParameterSpec params) throws GeneralSecurityException {
        generator.initialize(params);
        KeyPair keyPair = generator.generateKeyPair();
        agreement.init(keyPair.getPrivate());
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        this.ecParameterSpec = ecPublicKey.getParams();
        ECPoint w = ecPublicKey.getW();
        byte[] encoded = getEncoded(w, ecParameterSpec.getCurve());
        setE(encoded);
    }

    @Override
    public void computeK(byte[] f) throws GeneralSecurityException {
        KeyFactory keyFactory = SecurityUtils.getKeyFactory("EC");
        ECPublicKeySpec keySpec = new ECPublicKeySpec(getDecoded(f, ecParameterSpec.getCurve()), ecParameterSpec);
        PublicKey yourPubKey = keyFactory.generatePublic(keySpec);
        agreement.doPhase(yourPubKey, true);
        setK(new BigInteger(1, agreement.generateSecret()));
    }

    /**
     * SECG 2.3.4 Octet String to ECPoint
     */
    private static ECPoint getDecoded(byte[] M, EllipticCurve curve) {
        int elementSize = getElementSize(curve);
        if (M.length != 2 * elementSize + 1 || M[0] != 0x04) {
            throw new SSHRuntimeException("Invalid 'f' for Elliptic Curve " + curve.toString());
        }
        byte[] xBytes = new byte[elementSize];
        byte[] yBytes = new byte[elementSize];
        System.arraycopy(M, 1, xBytes, 0, elementSize);
        System.arraycopy(M, 1 + elementSize, yBytes, 0, elementSize);
        return new ECPoint(new BigInteger(1, xBytes), new BigInteger(1, yBytes));
    }

    /**
     * SECG 2.3.3 ECPoint to Octet String
     */
    private static byte[] getEncoded(ECPoint point, EllipticCurve curve) {
        int elementSize = getElementSize(curve);
        byte[] M = new byte[2 * elementSize + 1];
        M[0] = 0x04;

        byte[] xBytes = stripLeadingZeroes(point.getAffineX().toByteArray());
        byte[] yBytes = stripLeadingZeroes(point.getAffineY().toByteArray());
        System.arraycopy(xBytes, 0, M, 1 + elementSize - xBytes.length, xBytes.length);
        System.arraycopy(yBytes, 0, M, 1 + 2 * elementSize - yBytes.length, yBytes.length);
        return M;
    }

    private static byte[] stripLeadingZeroes(byte[] bytes) {
        int start = 0;
        while (bytes[start] == 0x0) {
            start++;
        }

        return Arrays.copyOfRange(bytes, start, bytes.length);
    }

    private static int getElementSize(EllipticCurve curve) {
        int fieldSize = curve.getField().getFieldSize();
        return (fieldSize + 7) / 8;
    }
}
