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
import net.schmizz.sshj.transport.random.Random;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class Curve25519DH extends DHBase {

    private byte[] secretKey;

    public Curve25519DH() {
        super("ECDSA", "ECDH");
    }

    @Override
    void computeK(byte[] f) throws GeneralSecurityException {
        byte[] k = new byte[32];
        djb.Curve25519.curve(k, secretKey, f);
        setK(new BigInteger(1, k));
    }

    @Override
    public void init(AlgorithmParameterSpec params, Factory<Random> randomFactory) throws GeneralSecurityException {
        Random random = randomFactory.create();
        byte[] secretBytes =  new byte[32];
        random.fill(secretBytes);
        byte[] publicBytes = new byte[32];
        djb.Curve25519.keygen(publicBytes, null, secretBytes);
        this.secretKey = Arrays.copyOf(secretBytes, secretBytes.length);
        setE(publicBytes);
    }

    /**
     * TODO want to figure out why BouncyCastle does not work.
     * @return The initialized curve25519 parameter spec
     */
    public static AlgorithmParameterSpec getCurve25519Params() {
        X9ECParameters ecP = CustomNamedCurves.getByName("curve25519");
        return new ECParameterSpec(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
    }
}
