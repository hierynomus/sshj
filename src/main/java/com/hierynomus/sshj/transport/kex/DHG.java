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
package com.hierynomus.sshj.transport.kex;

import net.schmizz.sshj.transport.digest.Digest;
import net.schmizz.sshj.transport.kex.AbstractDHG;
import net.schmizz.sshj.transport.kex.DH;
import net.schmizz.sshj.transport.kex.DHBase;

import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;

/**
 *
 */
public class DHG extends AbstractDHG {
    private BigInteger group;
    private BigInteger generator;

    public DHG(BigInteger group, BigInteger generator, Digest digest) {
        super(new DH(), digest);
        this.group = group;
        this.generator = generator;
    }

    @Override
    protected void initDH(DHBase dh) throws GeneralSecurityException {
        dh.init(new DHParameterSpec(group, generator), trans.getConfig().getRandomFactory());
    }
}
