/*
 * Copyright 2010 Shikhar Bhushan
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
    private BigInteger f; // your public key
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

    public void setF(BigInteger f) {
        this.f = f;
    }

    public void setG(BigInteger g) {
        this.g = g;
    }

    public void setP(BigInteger p) {
        this.p = p;
    }

    public byte[] getE()
            throws GeneralSecurityException {
        if (e == null) {
            generator.initialize(new DHParameterSpec(p, g));
            final KeyPair kp = generator.generateKeyPair();
            agreement.init(kp.getPrivate());
            e = ((javax.crypto.interfaces.DHPublicKey) kp.getPublic()).getY();
        }
        return e.toByteArray();
    }

    public byte[] getK()
            throws GeneralSecurityException {
        if (K == null) {
            final KeyFactory keyFactory = SecurityUtils.getKeyFactory("DH");
            final DHPublicKeySpec keySpec = new DHPublicKeySpec(f, p, g);
            final PublicKey yourPubKey = keyFactory.generatePublic(keySpec);
            agreement.doPhase(yourPubKey, true);
            K = new BigInteger(agreement.generateSecret());
        }
        return K.toByteArray();
    }

}
