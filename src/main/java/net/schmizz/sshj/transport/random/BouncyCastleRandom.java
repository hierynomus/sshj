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
package net.schmizz.sshj.transport.random;

import org.bouncycastle.crypto.prng.RandomGenerator;
import org.bouncycastle.crypto.prng.VMPCRandomGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;

/**
 * BouncyCastle <code>Random</code>. This pseudo random number generator uses the a very fast PRNG from BouncyCastle.
 * The JRE random will be used when creating a new generator to add some random data to the seed.
 */
public class BouncyCastleRandom
        implements Random {

    private static final Logger logger = LoggerFactory.getLogger(BouncyCastleRandom.class);

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
        logger.info("Generating random seed from SecureRandom.");
        long t = System.currentTimeMillis();
        byte[] seed = new SecureRandom().generateSeed(8);
        logger.debug("Creating random seed took {} ms", System.currentTimeMillis() - t);
        random.addSeedMaterial(seed);
    }

    @Override
    public void fill(byte[] bytes, int start, int len) {
        random.nextBytes(bytes, start, len);
    }

    @Override
    public void fill(byte[] bytes) {
        random.nextBytes(bytes);
    }

}
