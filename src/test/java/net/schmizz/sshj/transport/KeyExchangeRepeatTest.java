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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Collections;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.transport.kex.KeyExchange;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class KeyExchangeRepeatTest {

    private TransportImpl transport;
    private DefaultConfig config;
    private KeyExchanger keyExchanger;

    @BeforeEach
    public void setup() throws GeneralSecurityException, TransportException {
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

        assertFalse(transport.isAuthenticated()); // sanity check
        assertTrue(!keyExchanger.isKexOngoing() && !keyExchanger.isKexDone()); // sanity check
    }

    @Test
    public void allowOnlyOneKeyExchangeBeforeAuthentication() throws TransportException {
        // First key exchange before authentication succeeds.
        performAndCheckKeyExchange();

        // Second key exchange attempt before authentication is ignored.
        keyExchanger.startKex(false);
        assertTrue(!keyExchanger.isKexOngoing() && keyExchanger.isKexDone());
    }

    @Test
    public void allowExtraKeyExchangesAfterAuthentication() throws TransportException {
        // Key exchange before authentication succeeds.
        performAndCheckKeyExchange();

        // Simulate authentication.
        when(transport.isAuthenticated()).thenReturn(true);

        // Key exchange after authentication succeeds too.
        performAndCheckKeyExchange();
    }

    private void performAndCheckKeyExchange() throws TransportException {
        // Start key exchange.
        keyExchanger.startKex(false);
        assertTrue(keyExchanger.isKexOngoing() && !keyExchanger.isKexDone());

        // Simulate the arrival of the expected packets from the server while checking the state of the exchange.
        keyExchanger.handle(Message.KEXINIT, getKexinitPacket());
        assertTrue(keyExchanger.isKexOngoing() && !keyExchanger.isKexDone());
        keyExchanger.handle(Message.KEXDH_31, new SSHPacket(Message.KEXDH_31));
        assertTrue(keyExchanger.isKexOngoing() && !keyExchanger.isKexDone());
        keyExchanger.handle(Message.NEWKEYS, new SSHPacket(Message.NEWKEYS));
        assertTrue(!keyExchanger.isKexOngoing() && keyExchanger.isKexDone()); // done
    }

    private SSHPacket getKexinitPacket() {
        SSHPacket kexinitPacket = new Proposal(config, Collections.emptyList(), false).getPacket();
        kexinitPacket.rpos(kexinitPacket.rpos() + 1);
        return kexinitPacket;
    }
}
