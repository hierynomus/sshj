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
package net.schmizz.sshj.userauth.method;

import com.hierynomus.sshj.key.KeyAlgorithm;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.signature.Signature;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.userauth.UserAuthException;
import net.schmizz.sshj.userauth.keyprovider.KeyProvider;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.LinkedList;
import java.util.Queue;

public abstract class KeyedAuthMethod
        extends AbstractAuthMethod {

    protected final KeyProvider kProv;
    private Queue<KeyAlgorithm> available;

    public KeyedAuthMethod(String name, KeyProvider kProv) {
        super(name);
        this.kProv = kProv;
    }

    private KeyAlgorithm getPublicKeyAlgorithm(KeyType keyType) throws TransportException {
        if (available == null) {
            available = new LinkedList<>(params.getTransport().getClientKeyAlgorithms(keyType));
        }
        return available.peek();
    }

    @Override
    public boolean shouldRetry() {
        if (available != null) {
            available.poll();
            return !available.isEmpty();
        }
        return false;
    }

    protected SSHPacket putPubKey(SSHPacket reqBuf)
            throws UserAuthException {
        PublicKey key;
        try {
            key = kProv.getPublic();
        } catch (IOException ioe) {
            throw new UserAuthException("Problem getting public key from " + kProv, ioe);
        }

        // public key as 2 strings: [ key type | key blob ]
        KeyType keyType = KeyType.fromKey(key);
        try {
            KeyAlgorithm ka = getPublicKeyAlgorithm(keyType);
            if (ka != null) {
                reqBuf.putString(ka.getKeyAlgorithm())
                        .putString(new Buffer.PlainBuffer().putPublicKey(key).getCompactData());
                return reqBuf;
            }
        } catch (IOException ioe) {
            throw new UserAuthException("No KeyAlgorithm configured for key " + keyType, ioe);
        }
        throw new UserAuthException("No KeyAlgorithm configured for key " + keyType);
    }

    protected SSHPacket putSig(SSHPacket reqBuf)
            throws UserAuthException {
        PrivateKey key;
        try {
            key = kProv.getPrivate();
        } catch (IOException ioe) {
            throw new UserAuthException("Problem getting private key from " + kProv, ioe);
        }

        final KeyType kt = KeyType.fromKey(key);
        Signature signature;
        try {
            signature = getPublicKeyAlgorithm(kt).newSignature();
        } catch (TransportException e) {
            throw new UserAuthException("No KeyAlgorithm configured for key " + kt);
        }

        signature.initSign(key);
        signature.update(new Buffer.PlainBuffer()
                .putString(params.getTransport().getSessionID())
                .putBuffer(reqBuf) // & rest of the data for sig
                .getCompactData());
        reqBuf.putSignature(signature.getSignatureName(), signature.encode(signature.sign()));
        return reqBuf;
    }

}
