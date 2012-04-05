/*
 * Copyright 2010-2012 sshj contributors
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
 *
 * This file may incorporate work covered by the following copyright and
 * permission notice:
 *
 *     Licensed to the Apache Software Foundation (ASF) under one
 *     or more contributor license agreements.  See the NOTICE file
 *     distributed with this work for additional information
 *     regarding copyright ownership.  The ASF licenses this file
 *     to you under the Apache License, Version 2.0 (the
 *     "License"); you may not use this file except in compliance
 *     with the License.  You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *      Unless required by applicable law or agreed to in writing,
 *      software distributed under the License is distributed on an
 *      "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *      KIND, either express or implied.  See the License for the
 *      specific language governing permissions and limitations
 *      under the License.
 */
package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.DisconnectReason;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.signature.Signature;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.transport.digest.Digest;
import net.schmizz.sshj.transport.digest.SHA1;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Base class for DHG key exchange algorithms. Implementations will only have to configure the required data on the
 * {@link DH} class in the
 */
public abstract class AbstractDHG
        implements KeyExchange {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private Transport trans;

    private final Digest sha1 = new SHA1();
    private final DH dh = new DH();

    private String V_S;
    private String V_C;
    private byte[] I_S;
    private byte[] I_C;

    private byte[] H;
    private PublicKey hostKey;

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
        return sha1;
    }

    @Override
    public PublicKey getHostKey() {
        return hostKey;
    }

    @Override
    public void init(Transport trans, String V_S, String V_C, byte[] I_S, byte[] I_C)
            throws GeneralSecurityException, TransportException {
        this.trans = trans;
        this.V_S = V_S;
        this.V_C = V_C;
        this.I_S = Arrays.copyOf(I_S, I_S.length);
        this.I_C = Arrays.copyOf(I_C, I_C.length);
        sha1.init();
        initDH(dh);

        log.info("Sending SSH_MSG_KEXDH_INIT");
        trans.write(new SSHPacket(Message.KEXDH_INIT).putMPInt(dh.getE()));
    }

    @Override
    public boolean next(Message msg, SSHPacket packet)
            throws GeneralSecurityException, TransportException {
        if (msg != Message.KEXDH_31)
            throw new TransportException(DisconnectReason.KEY_EXCHANGE_FAILED, "Unexpected packet: " + msg);

        log.info("Received SSH_MSG_KEXDH_REPLY");
        final byte[] K_S;
        final BigInteger f;
        final byte[] sig; // signature sent by server
        try {
            K_S = packet.readBytes();
            f = packet.readMPInt();
            sig = packet.readBytes();
            hostKey = new Buffer.PlainBuffer(K_S).readPublicKey();
        } catch (Buffer.BufferException be) {
            throw new TransportException(be);
        }

        dh.computeK(f);

        final Buffer.PlainBuffer buf = new Buffer.PlainBuffer()
                .putString(V_C)
                .putString(V_S)
                .putString(I_C)
                .putString(I_S)
                .putString(K_S)
                .putMPInt(dh.getE())
                .putMPInt(f)
                .putMPInt(dh.getK());
        sha1.update(buf.array(), buf.rpos(), buf.available());
        H = sha1.digest();

        Signature signature = Factory.Named.Util.create(trans.getConfig().getSignatureFactories(),
                                                        KeyType.fromKey(hostKey).toString());
        signature.init(hostKey, null);
        signature.update(H, 0, H.length);
        if (!signature.verify(sig))
            throw new TransportException(DisconnectReason.KEY_EXCHANGE_FAILED,
                                         "KeyExchange signature verification failed");
        return true;
    }

    protected abstract void initDH(DH dh)
            throws GeneralSecurityException;

}
