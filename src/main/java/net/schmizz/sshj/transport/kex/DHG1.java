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
package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.transport.digest.SHA1;

import javax.crypto.spec.DHParameterSpec;
import java.security.GeneralSecurityException;

/**
 * Diffie-Hellman key exchange with SHA-1 and Oakley Group 2 [RFC2409] (1024-bit MODP Group).
 *
 * @see <a href="http://www.ietf.org/rfc/rfc4253.txt">RFC 4253</a>
 *
 * TODO refactor away the (unneeded) class
 * @deprecated Replaced by {@link com.hierynomus.sshj.transport.kex.DHG} with {@link com.hierynomus.sshj.transport.kex.DHGroups}
 */
public class DHG1
        extends AbstractDHG {

    /** Named factory for DHG1 key exchange */
    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<KeyExchange> {

        @Override
        public KeyExchange create() {
            return new DHG1();
        }

        @Override
        public String getName() {
            return "diffie-hellman-group1-sha1";
        }
    }

    public DHG1() {
        super(new DH(), new SHA1());
    }

    @Override
    protected void initDH(DHBase dh) throws GeneralSecurityException {
        dh.init(new DHParameterSpec(DHGroupData.P1, DHGroupData.G), trans.getConfig().getRandomFactory());
    }
}
