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

import java.io.File;
import java.io.Reader;

/** A file key provider is initialized with a location of */
public interface FileKeyProvider
        extends KeyProvider {

    void init(File location);

    void init(File location, PasswordFinder pwdf);

    void init(Reader location);

    void init(Reader location, PasswordFinder pwdf);

    void init(String privateKey, String publicKey);

    void init(String privateKey, String publicKey, PasswordFinder pwdf);
}
