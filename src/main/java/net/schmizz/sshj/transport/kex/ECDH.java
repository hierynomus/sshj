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
import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.transport.random.Random;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

import static com.hierynomus.sshj.secg.SecgUtils.getDecoded;
import static com.hierynomus.sshj.secg.SecgUtils.getEncoded;

public class ECDH extends DHBase {

    private ECParameterSpec ecParameterSpec;

    public ECDH() {
        super("EC", "ECDH");
    }

    public void init(AlgorithmParameterSpec params, Factory<Random> randomFactory) throws GeneralSecurityException {
        generator.initialize(params);
        KeyPair keyPair = generator.generateKeyPair();
        agreement.init(keyPair.getPrivate());
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        this.ecParameterSpec = ecPublicKey.getParams();
        ECPoint w = ecPublicKey.getW();
        byte[] encoded = getEncoded(w, ecParameterSpec.getCurve());
        setE(encoded);
    }

    @Override
    public void computeK(byte[] f) throws GeneralSecurityException {
        KeyFactory keyFactory = SecurityUtils.getKeyFactory("EC");
        ECPublicKeySpec keySpec = new ECPublicKeySpec(getDecoded(f, ecParameterSpec.getCurve()), ecParameterSpec);
        PublicKey yourPubKey = keyFactory.generatePublic(keySpec);
        agreement.doPhase(yourPubKey, true);
        setK(new BigInteger(1, agreement.generateSecret()));
    }

}
