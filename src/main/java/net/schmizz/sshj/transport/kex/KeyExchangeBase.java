package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.transport.digest.Digest;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Arrays;

public abstract class KeyExchangeBase implements KeyExchange {
    protected Transport trans;

    protected final Digest digest;
    protected byte[] H;
    protected PublicKey hostKey;

    private String V_S;
    private String V_C;
    private byte[] I_S;
    private byte[] I_C;

    public KeyExchangeBase(Digest digest) {
        this.digest = digest;
    }

    @Override
    public void init(Transport trans, String V_S, String V_C, byte[] I_S, byte[] I_C) throws GeneralSecurityException, TransportException {
        this.trans = trans;
        this.V_S = V_S;
        this.V_C = V_C;
        this.I_S = Arrays.copyOf(I_S, I_S.length);
        this.I_C = Arrays.copyOf(I_C, I_C.length);
    }

    protected Buffer.PlainBuffer initializedBuffer() {
        return new Buffer.PlainBuffer()
                .putString(V_C)
                .putString(V_S)
                .putString(I_C)
                .putString(I_S);
    }

    @Override
    public byte[] getH() {
        return Arrays.copyOf(H, H.length);
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
