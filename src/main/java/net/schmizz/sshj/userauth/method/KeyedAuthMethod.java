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
 */
package net.schmizz.sshj.userauth.method;

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.signature.Signature;
import net.schmizz.sshj.userauth.UserAuthException;
import net.schmizz.sshj.userauth.keyprovider.KeyProvider;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

public abstract class KeyedAuthMethod
        extends AbstractAuthMethod {

    protected final KeyProvider kProv;

    public KeyedAuthMethod(String name, KeyProvider kProv) {
        super(name);
        this.kProv = kProv;
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
        reqBuf.putString(KeyType.fromKey(key).toString())
              .putString(new Buffer.PlainBuffer().putPublicKey(key).getCompactData());
        return reqBuf;
    }

    protected SSHPacket putSig(SSHPacket reqBuf)
            throws UserAuthException {
        PrivateKey key;
        try {
            key = kProv.getPrivate();
        } catch (IOException ioe) {
            throw new UserAuthException("Problem getting private key from " + kProv, ioe);
        }

        final String kt = KeyType.fromKey(key).toString();
        Signature sigger = Factory.Named.Util.create(params.getTransport().getConfig().getSignatureFactories(), kt);
        if (sigger == null)
            throw new UserAuthException("Could not create signature instance for " + kt + " key");

        sigger.init(null, key);
        sigger.update(new Buffer.PlainBuffer()
                              .putString(params.getTransport().getSessionID())
                              .putBuffer(reqBuf) // & rest of the data for sig
                              .getCompactData());
        reqBuf.putSignature(kt, sigger.sign());
        return reqBuf;
    }

}
