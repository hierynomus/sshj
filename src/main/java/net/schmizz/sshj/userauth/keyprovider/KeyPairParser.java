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
package net.schmizz.sshj.userauth.keyprovider;

import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.Resource;

import java.io.IOException;
import java.security.KeyPair;

/**
 * Parses the private key material behind a {@link Resource} into a {@link KeyPair}. One implementation
 * per private key encoding; {@link BaseFileKeyProvider} subclasses delegate their {@code readKeyPair()}
 * to the parser for their format.
 */
interface KeyPairParser {

    /**
     * @param resource the located private key material (may be read more than once, e.g. on a passphrase retry)
     * @param pwdf     supplies the passphrase for an encrypted key, or {@code null} for an unencrypted key
     * @return the parsed key pair
     * @throws IOException on a malformed key or a failed decryption
     */
    KeyPair parseKeyPair(Resource<?> resource, PasswordFinder pwdf) throws IOException;
}
