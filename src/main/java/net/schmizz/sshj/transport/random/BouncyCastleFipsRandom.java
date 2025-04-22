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

/**
 * BouncyCastle <code>Random</code>. This pseudo random number generator uses BouncyCastle fips.
 * The JRE random will be used when creating a new generator to add some random data to the seed.
 */
public class BouncyCastleFipsRandom extends SecureRandomProvider {

    /** Named factory for the BouncyCastle <code>Random</code> */
    public static class Factory
            implements net.schmizz.sshj.common.Factory<Random> {

        @Override
        public Random create() {
            return new BouncyCastleFipsRandom();
        }

    }


    public BouncyCastleFipsRandom() {
        super("DEFAULT", "BCFIPS");
    }
}
