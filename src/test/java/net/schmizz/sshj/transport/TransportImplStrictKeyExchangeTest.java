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

import java.lang.reflect.Field;

import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.common.DisconnectReason;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.EnumSource.Mode;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TransportImplStrictKeyExchangeTest {

    private final Config config = new DefaultConfig();
    private final Transport transport = new TransportImpl(config);
    private final KeyExchanger kexer = mock(KeyExchanger.class);
    private final Decoder decoder = mock(Decoder.class);

    @BeforeEach
    void setUp() throws Exception {
        Field kexerField = TransportImpl.class.getDeclaredField("kexer");
        kexerField.setAccessible(true);
        kexerField.set(transport, kexer);
        Field decoderField = TransportImpl.class.getDeclaredField("decoder");
        decoderField.setAccessible(true);
        decoderField.set(transport, decoder);
    }

    @Test
    void throwExceptionOnWrapDuringInitialKex() {
        when(kexer.isInitialKex()).thenReturn(true);
        when(decoder.isSequenceNumberAtMax()).thenReturn(true);

        assertThatExceptionOfType(TransportException.class).isThrownBy(
                () -> transport.handle(Message.KEXINIT, new SSHPacket(Message.KEXINIT))
        ).satisfies(e -> {
            assertThat(e.getDisconnectReason()).isEqualTo(DisconnectReason.KEY_EXCHANGE_FAILED);
            assertThat(e.getMessage()).isEqualTo("Sequence number of decoder is about to wrap during initial key exchange");
        });
    }

    @ParameterizedTest
    @EnumSource(value = Message.class, mode = Mode.EXCLUDE, names = {
        "DISCONNECT", "KEXINIT", "NEWKEYS", "KEXDH_INIT", "KEXDH_31", "KEX_DH_GEX_INIT", "KEX_DH_GEX_REPLY", "KEX_DH_GEX_REQUEST"
    })
    void forbidUnexpectedPacketsDuringStrictKeyExchange(Message message) {
        when(kexer.isInitialKex()).thenReturn(true);
        when(decoder.isSequenceNumberAtMax()).thenReturn(false);
        when(kexer.isStrictKex()).thenReturn(true);

        assertThatExceptionOfType(TransportException.class).isThrownBy(
                () -> transport.handle(message, new SSHPacket(message))
        ).satisfies(e -> {
            assertThat(e.getDisconnectReason()).isEqualTo(DisconnectReason.KEY_EXCHANGE_FAILED);
            assertThat(e.getMessage()).isEqualTo("Unexpected packet type during initial strict key exchange");
        });
    }

    @ParameterizedTest
    @EnumSource(value = Message.class, mode = Mode.INCLUDE, names = {
        "KEXINIT", "NEWKEYS", "KEXDH_INIT", "KEXDH_31", "KEX_DH_GEX_INIT", "KEX_DH_GEX_REPLY", "KEX_DH_GEX_REQUEST"
    })
    void expectedPacketsDuringStrictKeyExchangeAreHandled(Message message) throws Exception {
        when(kexer.isInitialKex()).thenReturn(true);
        when(decoder.isSequenceNumberAtMax()).thenReturn(false);
        when(kexer.isStrictKex()).thenReturn(true);
        SSHPacket sshPacket = new SSHPacket(message);

        assertThatCode(
                () -> transport.handle(message, sshPacket)
        ).doesNotThrowAnyException();

        verify(kexer).handle(message, sshPacket);
    }

    @Test
    void disconnectIsAllowedDuringStrictKeyExchange() {
        when(kexer.isInitialKex()).thenReturn(true);
        when(decoder.isSequenceNumberAtMax()).thenReturn(false);
        when(kexer.isStrictKex()).thenReturn(true);

        SSHPacket sshPacket = new SSHPacket();
        sshPacket.putUInt32(DisconnectReason.SERVICE_NOT_AVAILABLE.toInt());
        sshPacket.putString("service is down for maintenance");

        assertThatExceptionOfType(TransportException.class).isThrownBy(
                () -> transport.handle(Message.DISCONNECT, sshPacket)
        ).satisfies(e -> {
            assertThat(e.getDisconnectReason()).isEqualTo(DisconnectReason.SERVICE_NOT_AVAILABLE);
            assertThat(e.getMessage()).isEqualTo("service is down for maintenance");
        });
    }

}
