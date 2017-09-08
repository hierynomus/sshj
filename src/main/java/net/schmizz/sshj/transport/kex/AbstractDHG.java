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

import java.security.GeneralSecurityException;

/**
 * Base class for DHG key exchange algorithms. Implementations will only have to configure the required data on the
 * {@link DH} class in the
 */
public abstract class AbstractDHG extends AbstractDH
        implements KeyExchange {

    private final Logger log = LoggerFactory.getLogger(getClass());

    public AbstractDHG(DHBase dhBase, Digest digest) {
        super(dhBase, digest);
    }

    @Override
    public void init(Transport trans, String V_S, String V_C, byte[] I_S, byte[] I_C)
            throws GeneralSecurityException, TransportException {
        super.init(trans, V_S, V_C, I_S, I_C);
        digest.init();
        initDH(dh);

        log.debug("Sending SSH_MSG_KEXDH_INIT");
        trans.write(new SSHPacket(Message.KEXDH_INIT).putBytes(dh.getE()));
    }

    @Override
    public boolean next(Message msg, SSHPacket packet)
            throws GeneralSecurityException, TransportException {
        if (msg != Message.KEXDH_31)
            throw new TransportException(DisconnectReason.KEY_EXCHANGE_FAILED, "Unexpected packet: " + msg);

        log.debug("Received SSH_MSG_KEXDH_REPLY");
        final byte[] K_S;
        final byte[] f;
        final byte[] sig; // signature sent by server
        try {
            K_S = packet.readBytes();
            f = packet.readBytes();
            sig = packet.readBytes();
            hostKey = new Buffer.PlainBuffer(K_S).readPublicKey();
        } catch (Buffer.BufferException be) {
            throw new TransportException(be);
        }

        dh.computeK(f);

        final Buffer.PlainBuffer buf = initializedBuffer()
                .putString(K_S)
                .putBytes(dh.getE())
                .putBytes(f)
                .putMPInt(dh.getK());
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

    protected abstract void initDH(DHBase dh)
            throws GeneralSecurityException;

}
