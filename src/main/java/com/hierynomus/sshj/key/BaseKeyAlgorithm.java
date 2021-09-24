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
package com.hierynomus.sshj.key;

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.signature.Signature;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

public class BaseKeyAlgorithm implements KeyAlgorithm {
    private final String keyAlgorithm;
    private final Factory.Named<Signature> signature;
    private final KeyType keyFormat;

    public BaseKeyAlgorithm(String keyAlgorithm, Factory.Named<Signature> signature, KeyType keyFormat) {
        this.keyAlgorithm = keyAlgorithm;
        this.signature = signature;
        this.keyFormat = keyFormat;
    }

    public void putPubKeyIntoBuffer(PublicKey pk, Buffer<?> buf) {
        keyFormat.putPubKeyIntoBuffer(pk, buf);
    }

    @Override
    public PublicKey readPubKeyFromBuffer(Buffer<?> buf) throws GeneralSecurityException {
        return keyFormat.readPubKeyFromBuffer(buf);
    }

    @Override
    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    @Override
    public KeyType getKeyFormat() {
        return keyFormat;
    }

    @Override
    public Signature newSignature() {
        return this.signature.create();
    }
}
