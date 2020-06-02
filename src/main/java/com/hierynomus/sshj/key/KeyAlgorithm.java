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
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.signature.Signature;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

/**
 * In [RFC4252], the concept "public key algorithm" is used to establish
 * a relationship between one algorithm name, and:
 * <p>
 * A.  procedures used to generate and validate a private/public
 * keypair;
 * B.  a format used to encode a public key; and
 * C.  procedures used to calculate, encode, and verify a signature.
 */
public interface KeyAlgorithm {

    PublicKey readPubKeyFromBuffer(Buffer<?> buf) throws GeneralSecurityException;

    void putPubKeyIntoBuffer(PublicKey pk, Buffer<?> buf);

    String getKeyAlgorithm();

    KeyType getKeyFormat();

    Signature newSignature();
}
