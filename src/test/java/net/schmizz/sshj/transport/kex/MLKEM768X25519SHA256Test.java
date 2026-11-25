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

import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.condition.DisabledIf;
import com.hierynomus.sshj.test.MLKEM;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.common.Factory;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class MLKEM768X25519SHA256Test {

    @Test
    public void factoryHasIanaName() {
        assertEquals("mlkem768x25519-sha256", new MLKEM768X25519SHA256.Factory().getName());
    }

    @Test
    @DisabledIf(value = MLKEM.UNSUPPORTED, disabledReason = MLKEM.REASON)
    public void factoryProducesFreshInstances() {
        final MLKEM768X25519SHA256.Factory factory = new MLKEM768X25519SHA256.Factory();
        final KeyExchange first = factory.create();
        final KeyExchange second = factory.create();

        assertInstanceOf(MLKEM768X25519SHA256.class, first);
        assertInstanceOf(MLKEM768X25519SHA256.class, second);
        assertNotSame(first, second);
    }

    @Test
    @EnabledIf(value = MLKEM.SUPPORTED, disabledReason = "ML-KEM not supported on this runtime")
    public void registeredFirstInDefaultConfigWhenSupported() {
        final List<Factory.Named<KeyExchange>> factories = new DefaultConfig().getKeyExchangeFactories();
        assertEquals("mlkem768x25519-sha256", factories.get(0).getName());
    }

    @Test
    @DisabledIf(value = MLKEM.SUPPORTED, disabledReason = "ML-KEM is supported on this runtime")
    public void notAdvertisedInDefaultConfigWhenUnsupported() {
        for (final Factory.Named<KeyExchange> factory : new DefaultConfig().getKeyExchangeFactories()) {
            assertNotEquals("mlkem768x25519-sha256", factory.getName());
        }
    }

    @Test
    @DisabledIf(value = MLKEM.SUPPORTED, disabledReason = "ML-KEM is supported on this runtime")
    public void factoryRefusesToCreateWhenUnsupported() {
        assertThrows(IllegalStateException.class, () -> new MLKEM768X25519SHA256.Factory().create());
    }
}
