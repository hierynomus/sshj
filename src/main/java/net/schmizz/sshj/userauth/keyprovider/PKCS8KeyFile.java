/*
 * Copyright 2010 Shikhar Bhushan
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
package net.schmizz.sshj.userauth.keyprovider;

import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.PasswordUtils;
import net.schmizz.sshj.userauth.password.PrivateKeyFileResource;
import net.schmizz.sshj.userauth.password.Resource;
import org.bouncycastle.openssl.EncryptionException;
import org.bouncycastle.openssl.PEMReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/** Represents a PKCS8-encoded key file. This is the format used by OpenSSH and OpenSSL. */
public class PKCS8KeyFile implements FileKeyProvider {

    public static class Factory implements net.schmizz.sshj.common.Factory.Named<FileKeyProvider> {
        public FileKeyProvider create() {
            return new PKCS8KeyFile();
        }

        public String getName() {
            return "PKCS8";
        }
    }

    protected final Logger log = LoggerFactory.getLogger(getClass());
    protected PasswordFinder pwdf;
    protected File location;
    protected Resource resource;
    protected KeyPair kp;

    protected KeyType type;

    protected char[] passphrase; // for blanking out

    public PrivateKey getPrivate() throws IOException {
        return kp != null ? kp.getPrivate() : (kp = readKeyPair()).getPrivate();
    }

    public PublicKey getPublic() throws IOException {
        return kp != null ? kp.getPublic() : (kp = readKeyPair()).getPublic();
    }

    public KeyType getType() throws IOException {
        return type != null ? type : (type = KeyType.fromKey(getPublic()));
    }

    public void init(File location) {
        assert location != null;
        this.location = location;
        resource = new PrivateKeyFileResource(location.getAbsolutePath());
    }

    public void init(File location, PasswordFinder pwdf) {
        init(location);
        this.pwdf = pwdf;
    }

    protected org.bouncycastle.openssl.PasswordFinder makeBouncyPasswordFinder() {
        if (pwdf == null)
            return null;
        else
            return new org.bouncycastle.openssl.PasswordFinder() {
                public char[] getPassword() {
                    return passphrase = pwdf.reqPassword(resource);
                }
            };
    }

    protected KeyPair readKeyPair() throws IOException {
        KeyPair kp = null;
        org.bouncycastle.openssl.PasswordFinder pFinder = makeBouncyPasswordFinder();
        PEMReader r = null;
        Object o = null;
        try {
            for (; ;) {
                // while the PasswordFinder tells us we should retry
                try {
                    r = new PEMReader(new InputStreamReader(new FileInputStream(location)), pFinder);
                    o = r.readObject();
                } catch (EncryptionException e) {
                    if (pwdf.shouldRetry(resource))
                        continue;
                    else
                        throw e;
                } finally {
                    IOUtils.closeQuietly(r);
                }
                break;
            }
        } finally {
            PasswordUtils.blankOut(passphrase);
        }

        if (o == null)
            throw new IOException("Could not read key pair from: " + location);
        if (o instanceof KeyPair)
            kp = (KeyPair) o;
        else
            log.debug("Expected KeyPair, got {}", o);
        return kp;
    }

}
