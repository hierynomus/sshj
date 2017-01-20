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

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;

public abstract class DHBase {
    protected final KeyPairGenerator generator;
    protected final KeyAgreement agreement;

    private byte[] e; // my public key
    private BigInteger K; // shared secret key

    public DHBase(String generator, String agreement) {
        try {
            this.generator = SecurityUtils.getKeyPairGenerator(generator);
            this.agreement = SecurityUtils.getKeyAgreement(agreement);
        } catch (GeneralSecurityException e) {
            throw new SSHRuntimeException(e);
        }
    }

    abstract void computeK(byte[] f) throws GeneralSecurityException;

    public abstract void init(AlgorithmParameterSpec params, Factory<Random> randomFactory) throws GeneralSecurityException;

    void setE(byte[] e) {
        this.e = e;
    }

    void setK(BigInteger k) {
        K = k;
    }

    public byte[] getE() {
        return e;
    }

    public BigInteger getK() {
        return K;
    }
}
