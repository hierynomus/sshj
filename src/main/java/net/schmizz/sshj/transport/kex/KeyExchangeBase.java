package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;

import java.security.GeneralSecurityException;
import java.util.Arrays;

public abstract class KeyExchangeBase implements KeyExchange {
    protected Transport trans;

    private String V_S;
    private String V_C;
    private byte[] I_S;
    private byte[] I_C;

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
}
