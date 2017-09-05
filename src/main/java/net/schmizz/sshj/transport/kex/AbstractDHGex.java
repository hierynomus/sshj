/*
 * Copyright (C)2009 - SSHJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.common.*;
import net.schmizz.sshj.signature.Signature;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.transport.digest.Digest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;

public abstract class AbstractDHGex extends AbstractDH {
    private final Logger log = LoggerFactory.getLogger(getClass());

    private int minBits = 1024;
    private int maxBits = 8192;
    private int preferredBits = 2048;

    public AbstractDHGex(Digest digest) {
        super(new DH(), digest);
    }

    @Override
    public void init(Transport trans, String V_S, String V_C, byte[] I_S, byte[] I_C) throws GeneralSecurityException, TransportException {
        super.init(trans, V_S, V_C, I_S, I_C);
        digest.init();

        log.debug("Sending {}", Message.KEX_DH_GEX_REQUEST);
        trans.write(new SSHPacket(Message.KEX_DH_GEX_REQUEST).putUInt32(minBits).putUInt32(preferredBits).putUInt32(maxBits));
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
        byte[] f = buffer.readBytes();
        byte[] sig = buffer.readBytes();
        hostKey = new Buffer.PlainBuffer(K_S).readPublicKey();

        dh.computeK(f);
        BigInteger k = dh.getK();

        final Buffer.PlainBuffer buf = initializedBuffer()
                .putString(K_S)
                .putUInt32(minBits)
                .putUInt32(preferredBits)
                .putUInt32(maxBits)
                .putMPInt(((DH) dh).getP())
                .putMPInt(((DH) dh).getG())
                .putBytes(dh.getE())
                .putBytes(f)
                .putMPInt(k);
        digest.update(buf.array(), buf.rpos(), buf.available());
        H = digest.digest();
        Signature signature = Factory.Named.Util.create(trans.getConfig().getSignatureFactories(),
                KeyType.fromKey(hostKey).toString());
        signature.initVerify(hostKey);
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
        dh.init(new DHParameterSpec(p, g), trans.getConfig().getRandomFactory());
        log.debug("Sending {}", Message.KEX_DH_GEX_INIT);
        trans.write(new SSHPacket(Message.KEX_DH_GEX_INIT).putBytes(dh.getE()));
        return false;
    }
}
