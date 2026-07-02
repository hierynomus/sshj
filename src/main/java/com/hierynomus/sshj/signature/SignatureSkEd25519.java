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
package com.hierynomus.sshj.signature;

import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.signature.Signature;

/**
 * Signature for the {@code sk-ssh-ed25519@openssh.com} FIDO/U2F key type. The raw Ed25519
 * signature is used as-is in both directions.
 */
public class SignatureSkEd25519 extends AbstractSecurityKeySignature {

    public static class Factory implements net.schmizz.sshj.common.Factory.Named<Signature> {
        @Override
        public String getName() {
            return KeyType.SK_ED25519.toString();
        }

        @Override
        public Signature create() {
            return new SignatureSkEd25519();
        }
    }

    public SignatureSkEd25519() {
        super("Ed25519", KeyType.SK_ED25519.toString());
    }

    @Override
    protected byte[] sshSignatureToDevice(byte[] sshRawSignature) {
        return sshRawSignature;
    }

    @Override
    protected byte[] deviceSignatureToSsh(byte[] deviceSignature) {
        return deviceSignature;
    }
}
