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

import java.io.IOException;
import java.security.KeyPair;

/**
 * Key File implementation supporting PEM-encoded PKCS8 and PKCS1 formats with or without password-based encryption
 */
public class PKCS8KeyFile extends BaseFileKeyProvider {

    private final KeyPairParser parser = new Pkcs8KeyPairParser();

    public static class Factory implements net.schmizz.sshj.common.Factory.Named<FileKeyProvider> {

        @Override
        public FileKeyProvider create() {
            return new PKCS8KeyFile();
        }

        @Override
        public String getName() {
            return "PKCS8";
        }
    }

    @Override
    protected KeyPair readKeyPair() throws IOException {
        return parser.parseKeyPair(resource, pwdf);
    }

    @Override
    public String toString() {
        return "PKCS8KeyFile{resource=" + resource + "}";
    }
}
