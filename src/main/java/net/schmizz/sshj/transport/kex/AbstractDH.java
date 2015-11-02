package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.transport.digest.Digest;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Arrays;

public abstract class AbstractDH extends KeyExchangeBase {
    protected final Digest digest;
    protected final DHBase dh;

    protected byte[] H;
    protected PublicKey hostKey;

    public AbstractDH(DHBase dh, Digest digest) {
        this.dh = dh;
        this.digest = digest;
    }

    @Override
    public byte[] getH() {
        return Arrays.copyOf(H, H.length);
    }

    @Override
    public BigInteger getK() {
        return dh.getK();
    }

    @Override
    public Digest getHash() {
        return digest;
    }

    @Override
    public PublicKey getHostKey() {
        return hostKey;
    }

}
