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
package net.schmizz.sshj.userauth.keyprovider.pkcs;

import org.bouncycastle.openssl.PEMKeyPair;

import java.io.IOException;

/**
 * Converter from typed object to PEM Key Pair
 * @param <T> Object Type
 */
public interface KeyPairConverter<T> {
    /**
     * Get PEM Key Pair from typed object
     *
     * @param object Typed Object
     * @return PEM Key Pair
     * @throws IOException Thrown on conversion failures
     */
    PEMKeyPair getKeyPair(T object) throws IOException;
}
