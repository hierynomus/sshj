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
package net.schmizz.sshj.transport.random;

import org.bouncycastle.crypto.prng.RandomGenerator;
import org.bouncycastle.crypto.prng.VMPCRandomGenerator;

import java.security.SecureRandom;

/**
 * BouncyCastle <code>Random</code>. This pseudo random number generator uses the a very fast PRNG from BouncyCastle.
 * The JRE random will be used when creating a new generator to add some random data to the seed.
 */
public class BouncyCastleRandom
        implements Random {

    /** Named factory for the BouncyCastle <code>Random</code> */
    public static class Factory
            implements net.schmizz.sshj.common.Factory<Random> {

        @Override
        public Random create() {
            return new BouncyCastleRandom();
        }

    }

    private final RandomGenerator random = new VMPCRandomGenerator();

    public BouncyCastleRandom() {
        byte[] seed = new SecureRandom().generateSeed(8);
        random.addSeedMaterial(seed);
    }

    @Override
    public void fill(byte[] bytes, int start, int len) {
        random.nextBytes(bytes, start, len);
    }

}
