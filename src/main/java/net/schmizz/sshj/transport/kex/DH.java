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

import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.common.SecurityUtils;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

/** Diffie-Hellman key generator. */
public class DH {

    private BigInteger p;
    private BigInteger g;
    private BigInteger e; // my public key
    private BigInteger K; // shared secret key
    private final KeyPairGenerator generator;
    private final KeyAgreement agreement;

    public DH() {
        try {
            generator = SecurityUtils.getKeyPairGenerator("DH");
            agreement = SecurityUtils.getKeyAgreement("DH");
        } catch (GeneralSecurityException e) {
            throw new SSHRuntimeException(e);
        }
    }

    public void init(BigInteger p, BigInteger g)
            throws GeneralSecurityException {
        this.p = p;
        this.g = g;
        generator.initialize(new DHParameterSpec(p, g));
        final KeyPair kp = generator.generateKeyPair();
        agreement.init(kp.getPrivate());
        e = ((javax.crypto.interfaces.DHPublicKey) kp.getPublic()).getY();
    }

    public void computeK(BigInteger f)
            throws GeneralSecurityException {
        final KeyFactory keyFactory = SecurityUtils.getKeyFactory("DH");
        final PublicKey yourPubKey = keyFactory.generatePublic(new DHPublicKeySpec(f, p, g));
        agreement.doPhase(yourPubKey, true);
        K = new BigInteger(1, agreement.generateSecret());
    }

    public BigInteger getE() {
        return e;
    }

    public BigInteger getK() {
        return K;
    }

}
