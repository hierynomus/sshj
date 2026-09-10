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

import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.common.Factory;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;

public class MLKEM768X25519SHA256Test {

    @Test
    public void factoryHasIanaName() {
        assertEquals("mlkem768x25519-sha256", new MLKEM768X25519SHA256.Factory().getName());
    }

    @Test
    public void factoryProducesFreshInstances() {
        final MLKEM768X25519SHA256.Factory factory = new MLKEM768X25519SHA256.Factory();
        final KeyExchange first = factory.create();
        final KeyExchange second = factory.create();

        assertInstanceOf(MLKEM768X25519SHA256.class, first);
        assertInstanceOf(MLKEM768X25519SHA256.class, second);
        assertNotSame(first, second);
    }

    @Test
    public void registeredFirstInDefaultConfig() {
        final List<Factory.Named<KeyExchange>> factories = new DefaultConfig().getKeyExchangeFactories();
        assertEquals("mlkem768x25519-sha256", factories.get(0).getName());
    }
}
