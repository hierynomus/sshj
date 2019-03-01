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

import net.schmizz.sshj.transport.digest.SHA256;

import java.security.GeneralSecurityException;

public class Curve25519SHA256 extends AbstractDHG {
    /** Named factory for Curve25519SHA256 key exchange */
    public static class FactoryLibSsh
            implements net.schmizz.sshj.common.Factory.Named<KeyExchange> {

        @Override
        public KeyExchange create() {
            return new Curve25519SHA256();
        }

        @Override
        public String getName() {
            return "curve25519-sha256@libssh.org";
        }
    }

    /** Named factory for Curve25519SHA256 key exchange */
    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<KeyExchange> {

        @Override
        public KeyExchange create() {
            return new Curve25519SHA256();
        }

        @Override
        public String getName() {
            return "curve25519-sha256";
        }
    }

    public Curve25519SHA256() {
        super(new Curve25519DH(), new SHA256());
    }

    @Override
    protected void initDH(DHBase dh) throws GeneralSecurityException {
        dh.init(Curve25519DH.getCurve25519Params(), trans.getConfig().getRandomFactory());
    }
}
