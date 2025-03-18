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
package net.schmizz.keepalive;

import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.connection.ConnectionImpl;
import net.schmizz.sshj.transport.Transport;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class HeartbeaterTest {

  @Test
  void ignoreMessageContainsData() throws Exception {
    Transport transport = mock(Transport.class);
    when(transport.getConfig()).thenReturn(new DefaultConfig());
    ArgumentCaptor<SSHPacket> sshPacketCaptor = ArgumentCaptor.forClass(SSHPacket.class);
    when(transport.write(sshPacketCaptor.capture())).thenReturn(0L);
    ConnectionImpl connection = new ConnectionImpl(transport, KeepAliveProvider.HEARTBEAT);

    KeepAlive heartbeater = connection.getKeepAlive();
    assertThat(heartbeater).isInstanceOf(Heartbeater.class);

    heartbeater.doKeepAlive();

    SSHPacket sshPacket = sshPacketCaptor.getValue();
    assertThat(sshPacket.readMessageID()).isEqualTo(Message.IGNORE);
    assertThat(sshPacket.readBytes()).isNotNull();
  }

}
