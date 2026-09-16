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
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;

/**
 * Regression/behavior tests for parsing {@code SSH_MSG_EXT_INFO} (RFC 8308) and extracting the
 * {@code server-sig-algs} extension.
 */
class TransportImplExtInfoTest {

    private final Config config = new DefaultConfig();
    private final TransportImpl transport = new TransportImpl(config);
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
    void defaultsToEmptyBeforeAnyExtInfoIsReceived() {
        assertThat(transport.getServerSignatureAlgorithms()).isEmpty();
    }

    @Test
    void parsesServerSigAlgsFromExtInfo() throws Exception {
        SSHPacket packet = extInfoPacket(entry("server-sig-algs", "rsa-sha2-256,rsa-sha2-512,ssh-rsa"));

        transport.handle(Message.EXT_INFO, packet);

        assertThat(transport.getServerSignatureAlgorithms())
                .containsExactly("rsa-sha2-256", "rsa-sha2-512", "ssh-rsa");
    }

    @Test
    void skipsUnknownExtensionsWithoutLosingBufferPosition() throws Exception {
        SSHPacket packet = extInfoPacket(
                entry("delay-compression", "zlib@openssh.com,none"),
                entry("server-sig-algs", "ssh-ed25519"),
                entry("no-flow-control", "1"));

        transport.handle(Message.EXT_INFO, packet);

        assertThat(transport.getServerSignatureAlgorithms()).containsExactly("ssh-ed25519");
    }

    @Test
    void emptyExtInfoLeavesServerSignatureAlgorithmsEmpty() throws Exception {
        SSHPacket packet = extInfoPacket();

        transport.handle(Message.EXT_INFO, packet);

        assertThat(transport.getServerSignatureAlgorithms()).isEmpty();
    }

    @Test
    void repeatedServerSigAlgsExtensionLastOneWins() throws Exception {
        SSHPacket packet = extInfoPacket(
                entry("server-sig-algs", "ssh-rsa"),
                entry("server-sig-algs", "ssh-ed25519"));

        transport.handle(Message.EXT_INFO, packet);

        assertThat(transport.getServerSignatureAlgorithms()).containsExactly("ssh-ed25519");
    }

    @Test
    void truncatedExtInfoThrowsTransportException() {
        SSHPacket packet = new SSHPacket();
        packet.putUInt32(2); // declares 2 extensions but provides none

        assertThatExceptionOfType(TransportException.class).isThrownBy(
                () -> transport.handle(Message.EXT_INFO, packet)
        );
    }

    private static String[] entry(String name, String value) {
        return new String[]{name, value};
    }

    private static SSHPacket extInfoPacket(String[]... entries) {
        // handle()/gotExtInfo() receive the buffer positioned right after the message-type
        // byte (already consumed by the decoder), so the payload starts with a plain SSHPacket -
        // mirrors TransportImplStrictKeyExchangeTest.disconnectIsAllowedDuringStrictKeyExchange().
        SSHPacket packet = new SSHPacket();
        packet.putUInt32(entries.length);
        for (String[] entry : entries) {
            packet.putString(entry[0]);
            packet.putString(entry[1]);
        }
        return packet;
    }
}
