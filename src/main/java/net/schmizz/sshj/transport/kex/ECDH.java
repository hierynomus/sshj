package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.common.SecurityUtils;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;

import static net.schmizz.sshj.transport.kex.SecgUtils.getDecoded;
import static net.schmizz.sshj.transport.kex.SecgUtils.getEncoded;

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

}
