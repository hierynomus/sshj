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

import java.math.BigInteger;
import java.util.Collections;
import java.util.List;

import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.common.DisconnectReason;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.transport.kex.KeyExchange;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class KeyExchangerStrictKeyExchangeTest {

    private TransportImpl transport;
    private DefaultConfig config;
    private KeyExchanger keyExchanger;

    @BeforeEach
    void setUp() throws Exception {
        KeyExchange kex = mock(KeyExchange.class, Mockito.RETURNS_DEEP_STUBS);
        transport = mock(TransportImpl.class, Mockito.RETURNS_DEEP_STUBS);
        config = new DefaultConfig() {
            @Override
            protected void initKeyExchangeFactories() {
                setKeyExchangeFactories(Collections.singletonList(new Factory.Named<>() {
                    @Override
                    public KeyExchange create() {
                        return kex;
                    }

                    @Override
                    public String getName() {
                        return "mock-kex";
                    }
                }));
            }
        };
        when(transport.getConfig()).thenReturn(config);
        when(transport.getServerID()).thenReturn("some server id");
        when(transport.getClientID()).thenReturn("some client id");
        when(kex.next(any(), any())).thenReturn(true);
        when(kex.getH()).thenReturn(new byte[0]);
        when(kex.getK()).thenReturn(BigInteger.ZERO);
        when(kex.getHash().digest()).thenReturn(new byte[10]);

        keyExchanger = new KeyExchanger(transport);
        keyExchanger.addHostKeyVerifier(new PromiscuousVerifier());
    }

    @Test
    void initialConditions() {
        assertThat(keyExchanger.isKexDone()).isFalse();
        assertThat(keyExchanger.isKexOngoing()).isFalse();
        assertThat(keyExchanger.isStrictKex()).isFalse();
        assertThat(keyExchanger.isInitialKex()).isTrue();
    }

    @Test
    void startInitialKex() throws Exception {
        ArgumentCaptor<SSHPacket> sshPacketCaptor = ArgumentCaptor.forClass(SSHPacket.class);
        when(transport.write(sshPacketCaptor.capture())).thenReturn(0L);

        keyExchanger.startKex(false);

        assertThat(keyExchanger.isKexDone()).isFalse();
        assertThat(keyExchanger.isKexOngoing()).isTrue();
        assertThat(keyExchanger.isStrictKex()).isFalse();
        assertThat(keyExchanger.isInitialKex()).isTrue();

        SSHPacket sshPacket = sshPacketCaptor.getValue();
        List<String> kex = new Proposal(sshPacket).getKeyExchangeAlgorithms();
        assertThat(kex).endsWith("kex-strict-c-v00@openssh.com");
    }

    @Test
    void receiveKexInitWithoutServerFlag() throws Exception {
        keyExchanger.startKex(false);

        keyExchanger.handle(Message.KEXINIT, getKexInitPacket(false));

        assertThat(keyExchanger.isKexDone()).isFalse();
        assertThat(keyExchanger.isKexOngoing()).isTrue();
        assertThat(keyExchanger.isStrictKex()).isFalse();
        assertThat(keyExchanger.isInitialKex()).isTrue();
    }

    @Test
    void finishNonStrictKex() throws Exception {
        keyExchanger.startKex(false);

        keyExchanger.handle(Message.KEXINIT, getKexInitPacket(false));
        keyExchanger.handle(Message.KEXDH_31, new SSHPacket(Message.KEXDH_31));
        keyExchanger.handle(Message.NEWKEYS, new SSHPacket(Message.NEWKEYS));

        assertThat(keyExchanger.isKexDone()).isTrue();
        assertThat(keyExchanger.isKexOngoing()).isFalse();
        assertThat(keyExchanger.isStrictKex()).isFalse();
        assertThat(keyExchanger.isInitialKex()).isFalse();

        verify(transport.getEncoder(), never()).resetSequenceNumber();
        verify(transport.getDecoder(), never()).resetSequenceNumber();
    }

    @Test
    void receiveKexInitWithServerFlag() throws Exception {
        keyExchanger.startKex(false);

        keyExchanger.handle(Message.KEXINIT, getKexInitPacket(true));

        assertThat(keyExchanger.isKexDone()).isFalse();
        assertThat(keyExchanger.isKexOngoing()).isTrue();
        assertThat(keyExchanger.isStrictKex()).isTrue();
        assertThat(keyExchanger.isInitialKex()).isTrue();
    }

    @Test
    void strictKexInitIsNotFirstPacket() throws Exception {
        when(transport.getDecoder().getSequenceNumber()).thenReturn(1L);
        keyExchanger.startKex(false);

        assertThatExceptionOfType(TransportException.class).isThrownBy(
                () -> keyExchanger.handle(Message.KEXINIT, getKexInitPacket(true))
        ).satisfies(e -> {
            assertThat(e.getDisconnectReason()).isEqualTo(DisconnectReason.KEY_EXCHANGE_FAILED);
            assertThat(e.getMessage()).isEqualTo("SSH_MSG_KEXINIT was not first package during strict key exchange");
        });
    }

    @Test
    void finishStrictKex() throws Exception {
        keyExchanger.startKex(false);

        keyExchanger.handle(Message.KEXINIT, getKexInitPacket(true));
        verify(transport.getEncoder(), never()).resetSequenceNumber();
        keyExchanger.handle(Message.KEXDH_31, new SSHPacket(Message.KEXDH_31));
        verify(transport.getEncoder()).resetSequenceNumber();
        verify(transport.getDecoder(), never()).resetSequenceNumber();
        keyExchanger.handle(Message.NEWKEYS, new SSHPacket(Message.NEWKEYS));
        verify(transport.getDecoder()).resetSequenceNumber();

        assertThat(keyExchanger.isKexDone()).isTrue();
        assertThat(keyExchanger.isKexOngoing()).isFalse();
        assertThat(keyExchanger.isStrictKex()).isTrue();
        assertThat(keyExchanger.isInitialKex()).isFalse();
    }

    @Test
    void noClientFlagInSecondStrictKex() throws Exception {
        keyExchanger.startKex(false);
        keyExchanger.handle(Message.KEXINIT, getKexInitPacket(true));
        keyExchanger.handle(Message.KEXDH_31, new SSHPacket(Message.KEXDH_31));
        keyExchanger.handle(Message.NEWKEYS, new SSHPacket(Message.NEWKEYS));

        ArgumentCaptor<SSHPacket> sshPacketCaptor = ArgumentCaptor.forClass(SSHPacket.class);
        when(transport.write(sshPacketCaptor.capture())).thenReturn(0L);
        when(transport.isAuthenticated()).thenReturn(true);

        keyExchanger.startKex(false);

        assertThat(keyExchanger.isKexDone()).isFalse();
        assertThat(keyExchanger.isKexOngoing()).isTrue();
        assertThat(keyExchanger.isStrictKex()).isTrue();
        assertThat(keyExchanger.isInitialKex()).isFalse();

        SSHPacket sshPacket = sshPacketCaptor.getValue();
        List<String> kex = new Proposal(sshPacket).getKeyExchangeAlgorithms();
        assertThat(kex).doesNotContain("kex-strict-c-v00@openssh.com");
    }

    @Test
    void serverFlagIsIgnoredInSecondKex() throws Exception {
        keyExchanger.startKex(false);
        keyExchanger.handle(Message.KEXINIT, getKexInitPacket(false));
        keyExchanger.handle(Message.KEXDH_31, new SSHPacket(Message.KEXDH_31));
        keyExchanger.handle(Message.NEWKEYS, new SSHPacket(Message.NEWKEYS));

        ArgumentCaptor<SSHPacket> sshPacketCaptor = ArgumentCaptor.forClass(SSHPacket.class);
        when(transport.write(sshPacketCaptor.capture())).thenReturn(0L);
        when(transport.isAuthenticated()).thenReturn(true);

        keyExchanger.startKex(false);
        keyExchanger.handle(Message.KEXINIT, getKexInitPacket(true));

        assertThat(keyExchanger.isKexDone()).isFalse();
        assertThat(keyExchanger.isKexOngoing()).isTrue();
        assertThat(keyExchanger.isStrictKex()).isFalse();
        assertThat(keyExchanger.isInitialKex()).isFalse();

        SSHPacket sshPacket = sshPacketCaptor.getValue();
        List<String> kex = new Proposal(sshPacket).getKeyExchangeAlgorithms();
        assertThat(kex).doesNotContain("kex-strict-c-v00@openssh.com");
    }

    private SSHPacket getKexInitPacket(boolean withServerFlag) {
        SSHPacket kexinitPacket = new Proposal(config, Collections.emptyList(), true).getPacket();
        if (withServerFlag) {
            int finalWpos = kexinitPacket.wpos();
            kexinitPacket.wpos(22);
            kexinitPacket.putString("mock-kex,kex-strict-s-v00@openssh.com");
            kexinitPacket.wpos(finalWpos);
        }
        kexinitPacket.rpos(kexinitPacket.rpos() + 1);
        return kexinitPacket;
    }

}
