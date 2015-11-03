package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.transport.digest.Digest;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Arrays;

public abstract class AbstractDH extends KeyExchangeBase {
    protected final DHBase dh;

    public AbstractDH(DHBase dh, Digest digest) {
        super(digest);
        this.dh = dh;
    }

    @Override
    public BigInteger getK() {
        return dh.getK();
    }
}
