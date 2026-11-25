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
package net.schmizz.sshj.transport;

import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TransportImplTimeoutTest {

    @Test
    void shouldUseDefaultTimeoutFromConfig() {
        Config config = new DefaultConfig();
        Transport transport = new TransportImpl(config);

        assertThat(transport.getTimeoutMs()).isEqualTo(30000);
    }

    @Test
    void shouldUseCustomTimeoutFromConfig() {
        Config config = new DefaultConfig();
        config.setTimeoutMs(60000);
        Transport transport = new TransportImpl(config);

        assertThat(transport.getTimeoutMs()).isEqualTo(60000);
    }

    @Test
    void shouldAllowChangingTimeoutAfterCreation() {
        Config config = new DefaultConfig();
        Transport transport = new TransportImpl(config);

        transport.setTimeoutMs(45000);

        assertThat(transport.getTimeoutMs()).isEqualTo(45000);
    }
}
