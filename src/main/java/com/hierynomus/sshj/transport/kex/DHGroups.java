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
package com.hierynomus.sshj.transport.kex;

import net.schmizz.sshj.transport.digest.Digest;
import net.schmizz.sshj.transport.digest.SHA1;
import net.schmizz.sshj.transport.digest.SHA256;
import net.schmizz.sshj.transport.digest.SHA512;
import net.schmizz.sshj.transport.kex.KeyExchange;

import java.math.BigInteger;

import static net.schmizz.sshj.transport.kex.DHGroupData.*;

/**
 * Factory methods for Diffie Hellmann KEX algorithms based on MODP groups / Oakley Groups
 *
 * - https://tools.ietf.org/html/rfc4253
 * - https://tools.ietf.org/html/draft-ietf-curdle-ssh-modp-dh-sha2-01
 */
@SuppressWarnings("PMD.MethodNamingConventions")
public class DHGroups {

    public static DHGroups.Factory Group1SHA1() {
        return new DHGroups.Factory("diffie-hellman-group1-sha1", P1, G, new SHA1.Factory());
    }

    public static DHGroups.Factory Group14SHA1() {
        return new DHGroups.Factory("diffie-hellman-group14-sha1", P14, G, new SHA1.Factory());
    }

    public static DHGroups.Factory Group14SHA256() {
        return new DHGroups.Factory("diffie-hellman-group14-sha256", P14, G, new SHA256.Factory());
    }

    public static DHGroups.Factory Group15SHA512() {
        return new DHGroups.Factory("diffie-hellman-group15-sha512", P15, G, new SHA512.Factory());
    }

    public static DHGroups.Factory Group16SHA512() {
        return new DHGroups.Factory("diffie-hellman-group16-sha512", P16, G, new SHA512.Factory());
    }

    public static DHGroups.Factory Group17SHA512() {
        return new DHGroups.Factory("diffie-hellman-group17-sha512", P17, G, new SHA512.Factory());
    }

    public static DHGroups.Factory Group18SHA512() {
        return new DHGroups.Factory("diffie-hellman-group18-sha512", P18, G, new SHA512.Factory());
    }

    /**
     * Named factory for DHG1 key exchange
     */
    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<KeyExchange> {

        private String name;
        private BigInteger group;
        private BigInteger generator;
        private Factory.Named<Digest> digestFactory;

        public Factory(String name, BigInteger group, BigInteger generator, Named<Digest> digestFactory) {
            this.name = name;
            this.group = group;
            this.generator = generator;
            this.digestFactory = digestFactory;
        }

        @Override
        public KeyExchange create() {
            return new DHG(group, generator, digestFactory.create());
        }

        @Override
        public String getName() {
            return name;
        }
    }

}
