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

import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.userauth.password.*;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public abstract class BaseFileKeyProvider implements FileKeyProvider {
    protected Resource<?> resource;
    protected PasswordFinder pwdf;
    protected KeyPair kp;

    protected KeyType type;

    @Override
    public void init(Reader location) {
        assert location != null;
        resource = new PrivateKeyReaderResource(location);
    }

    @Override
    public void init(Reader location, PasswordFinder pwdf) {
        init(location);
        this.pwdf = pwdf;
    }

    @Override
    public void init(File location) {
        assert location != null;
        resource = new PrivateKeyFileResource(location.getAbsoluteFile());
    }

    @Override
    public void init(File location, PasswordFinder pwdf) {
        init(location);
        this.pwdf = pwdf;
    }

    @Override
    public void init(String privateKey, String publicKey) {
        assert privateKey != null;
        assert publicKey == null;
        resource = new PrivateKeyStringResource(privateKey);
    }

    @Override
    public void init(String privateKey, String publicKey, PasswordFinder pwdf) {
        init(privateKey, publicKey);
        this.pwdf = pwdf;
    }

    @Override
    public PrivateKey getPrivate()
            throws IOException {
        return kp != null ? kp.getPrivate() : (kp = readKeyPair()).getPrivate();
    }

    @Override
    public PublicKey getPublic()
            throws IOException {
        return kp != null ? kp.getPublic() : (kp = readKeyPair()).getPublic();
    }

    @Override
    public KeyType getType()
            throws IOException {
        return type != null ? type : (type = KeyType.fromKey(getPublic()));
    }


    protected abstract KeyPair readKeyPair() throws IOException;
}
