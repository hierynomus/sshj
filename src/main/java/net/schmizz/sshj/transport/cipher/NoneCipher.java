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
package net.schmizz.sshj.transport.cipher;

/** Represents a no-op cipher. */
public class NoneCipher
        implements Cipher {

    /** Named factory for the no-op Cipher */
    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<Cipher> {

        @Override
        public Cipher create() {
            return new NoneCipher();
        }

        @Override
        public String getName() {
            return "none";
        }
    }

    @Override
    public int getBlockSize() {
        return 8;
    }

    @Override
    public int getIVSize() {
        return 8;
    }

    @Override
    public void init(Mode mode, byte[] bytes, byte[] bytes1) {
    }

    @Override
    public void update(byte[] input, int inputOffset, int inputLen) {
    }

}
