package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.common.SecurityUtils;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;

abstract class DHBase {
    protected final KeyPairGenerator generator;
    protected final KeyAgreement agreement;

    private byte[] e; // my public key
    private BigInteger K; // shared secret key

    public DHBase(String generator, String agreement) {
        try {
            this.generator = SecurityUtils.getKeyPairGenerator(generator);
            this.agreement = SecurityUtils.getKeyAgreement(agreement);
        } catch (GeneralSecurityException e) {
            throw new SSHRuntimeException(e);
        }
    }

    abstract void computeK(byte[] f) throws GeneralSecurityException;

    protected abstract void init(AlgorithmParameterSpec params) throws GeneralSecurityException;

    void setE(byte[] e) {
        this.e = e;
    }

    void setK(BigInteger k) {
        K = k;
    }

    public byte[] getE() {
        return e;
    }

    public BigInteger getK() {
        return K;
    }
}
