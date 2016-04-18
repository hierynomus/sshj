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
package net.schmizz.sshj.transport.digest;

import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.common.SecurityUtils;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/** Base class for Digest algorithms based on the JCE provider. */
public class BaseDigest
        implements Digest {

    private final String algorithm;
    private final int bsize;
    private MessageDigest md;

    /**
     * Create a new digest using the given algorithm and block size. The initialization and creation of the underlying
     * {@link MessageDigest} object will be done in the {@link #init()} method.
     *
     * @param algorithm the JCE algorithm to use for this digest
     * @param bsize     the block size of this digest
     */
    public BaseDigest(String algorithm, int bsize) {
        this.algorithm = algorithm;
        this.bsize = bsize;
    }

    @Override
    public byte[] digest() {
        return md.digest();
    }

    @Override
    public int getBlockSize() {
        return bsize;
    }

    @Override
    public void init() {
        try {
            md = SecurityUtils.getMessageDigest(algorithm);
        } catch (GeneralSecurityException e) {
            throw new SSHRuntimeException(e);
        }
    }

    @Override
    public void update(byte[] foo) {
        update(foo, 0, foo.length);
    }

    @Override
    public void update(byte[] foo, int start, int len) {
        md.update(foo, start, len);
    }

}
