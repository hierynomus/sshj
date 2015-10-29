package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.common.*;
import net.schmizz.sshj.signature.Signature;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.transport.digest.Digest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Arrays;

public abstract class AbstractDHGex extends KeyExchangeBase {
    private final Logger log = LoggerFactory.getLogger(getClass());

    private Digest digest;

    private int minBits = 1024;
    private int maxBits = 8192;
    private int preferredBits = 2048;

    private DH dh;
    private PublicKey hostKey;
    private byte[] H;

    public AbstractDHGex(Digest digest) {
        this.digest = digest;
    }

    @Override
    public void init(Transport trans, String V_S, String V_C, byte[] I_S, byte[] I_C) throws GeneralSecurityException, TransportException {
        super.init(trans, V_S, V_C, I_S, I_C);
        dh = new DH();
        digest.init();

        log.debug("Sending {}", Message.KEX_DH_GEX_REQUEST);
        trans.write(new SSHPacket(Message.KEX_DH_GEX_REQUEST).putUInt32(minBits).putUInt32(preferredBits).putUInt32(maxBits));
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

    @Override
    public boolean next(Message msg, SSHPacket buffer) throws GeneralSecurityException, TransportException {
        log.debug("Got message {}", msg);
        try {
            switch (msg) {
                case KEXDH_31:
                    return parseGexGroup(buffer);
                case KEX_DH_GEX_REPLY:
                    return parseGexReply(buffer);
            }
        } catch (Buffer.BufferException be) {
            throw new TransportException(be);
        }
        throw new TransportException("Unexpected message " + msg);
    }

    private boolean parseGexReply(SSHPacket buffer) throws Buffer.BufferException, GeneralSecurityException, TransportException {
        byte[] K_S = buffer.readBytes();
        BigInteger f = buffer.readMPInt();
        byte[] sig = buffer.readBytes();
        hostKey = new Buffer.PlainBuffer(K_S).readPublicKey();

        dh.computeK(f);
        BigInteger k = dh.getK();

        final Buffer.PlainBuffer buf = initializedBuffer()
                .putString(K_S)
                .putUInt32(minBits)
                .putUInt32(preferredBits)
                .putUInt32(maxBits)
                .putMPInt(dh.getP())
                .putMPInt(dh.getG())
                .putMPInt(dh.getE())
                .putMPInt(f)
                .putMPInt(k);
        digest.update(buf.array(), buf.rpos(), buf.available());
        H = digest.digest();
        Signature signature = Factory.Named.Util.create(trans.getConfig().getSignatureFactories(),
                KeyType.fromKey(hostKey).toString());
        signature.init(hostKey, null);
        signature.update(H, 0, H.length);
        if (!signature.verify(sig))
            throw new TransportException(DisconnectReason.KEY_EXCHANGE_FAILED,
                    "KeyExchange signature verification failed");
        return true;

    }

    private boolean parseGexGroup(SSHPacket buffer) throws Buffer.BufferException, GeneralSecurityException, TransportException {
        BigInteger p = buffer.readMPInt();
        BigInteger g = buffer.readMPInt();
        int bitLength = p.bitLength();
        if (bitLength < minBits || bitLength > maxBits) {
            throw new GeneralSecurityException("Server generated gex p is out of range (" + bitLength + " bits)");
        }
        log.debug("Received server p bitlength {}", bitLength);
        dh.init(p, g);
        log.debug("Sending {}", Message.KEX_DH_GEX_INIT);
        trans.write(new SSHPacket(Message.KEX_DH_GEX_INIT).putMPInt(dh.getE()));
        return false;
    }
}
