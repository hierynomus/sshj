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

import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.transport.random.Random;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

/** Diffie-Hellman key generator. */
public class DH extends DHBase {

    private BigInteger p;
    private BigInteger g;

    public DH() {
        super("DH", "DH");
    }

    @Override
    public void init(AlgorithmParameterSpec params, Factory<Random> randomFactory) throws GeneralSecurityException {
        if (!(params instanceof DHParameterSpec)) {
            throw new SSHRuntimeException("Wrong algorithm parameters for Diffie Hellman");
        }
        this.p = ((DHParameterSpec) params).getP();
        this.g = ((DHParameterSpec) params).getG();
        generator.initialize(params);
        final KeyPair kp = generator.generateKeyPair();
        agreement.init(kp.getPrivate());
        setE(((javax.crypto.interfaces.DHPublicKey) kp.getPublic()).getY().toByteArray());
    }

    @Override
    void computeK(byte[] f) throws GeneralSecurityException {
        final KeyFactory keyFactory = SecurityUtils.getKeyFactory("DH");
        final PublicKey yourPubKey = keyFactory.generatePublic(new DHPublicKeySpec(new BigInteger(f), p, g));
        agreement.doPhase(yourPubKey, true);
        setK(new BigInteger(1, agreement.generateSecret()));
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getG() {
        return g;
    }
}
