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
        this.init(location, (PasswordFinder) null);
    }

    @Override
    public void init(Reader location, PasswordFinder pwdf) {
        this.init(location, null, pwdf);
    }

    @Override
    public void init(Reader privateKey, Reader publicKey) {
        this.init(privateKey, publicKey, null);
    }

    @Override
    public void init(Reader privateKey, Reader publicKey, PasswordFinder pwdf) {
        assert publicKey == null;
        this.resource = new PrivateKeyReaderResource(privateKey);
        this.pwdf = pwdf;
    }

    @Override
    public void init(File location) {
        this.init(location, null);
    }

    @Override
    public void init(File location, PasswordFinder pwdf) {
        this.resource = new PrivateKeyFileResource(location.getAbsoluteFile());
        this.pwdf = pwdf;
    }

    @Override
    public void init(String privateKey, String publicKey) {
        this.init(privateKey, publicKey, null);
    }

    @Override
    public void init(String privateKey, String publicKey, PasswordFinder pwdf) {
        assert privateKey != null;
        assert publicKey == null;
        this.resource = new PrivateKeyStringResource(privateKey);
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
