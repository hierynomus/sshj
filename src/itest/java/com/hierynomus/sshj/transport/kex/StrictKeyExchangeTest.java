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

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.hierynomus.sshj.SshdContainer;
import net.schmizz.keepalive.KeepAlive;
import net.schmizz.keepalive.KeepAliveProvider;
import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.connection.ConnectionImpl;
import net.schmizz.sshj.transport.TransportException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.LoggerFactory;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Testcontainers
class StrictKeyExchangeTest {

    @Container
    private static final SshdContainer sshd = new SshdContainer();

    private final List<Logger> watchedLoggers = new ArrayList<>();
    private final ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();

    @BeforeEach
    void setUpLogWatcher() {
        logWatcher.start();
        setUpLogger("net.schmizz.sshj.transport.Decoder");
        setUpLogger("net.schmizz.sshj.transport.Encoder");
        setUpLogger("net.schmizz.sshj.transport.KeyExchanger");
    }

    @AfterEach
    void tearDown() {
        watchedLoggers.forEach(Logger::detachAndStopAllAppenders);
    }

    private void setUpLogger(String className) {
        Logger logger = ((Logger) LoggerFactory.getLogger(className));
        logger.addAppender(logWatcher);
        watchedLoggers.add(logger);
    }

    private static Stream<Arguments> strictKeyExchange() {
        Config defaultConfig = new DefaultConfig();
        Config heartbeaterConfig = new DefaultConfig();
        heartbeaterConfig.setKeepAliveProvider(new KeepAliveProvider() {
            @Override
            public KeepAlive provide(ConnectionImpl connection) {
                return new HotLoopHeartbeater(connection);
            }
        });
        return Stream.of(defaultConfig, heartbeaterConfig).map(Arguments::of);
    }

    @MethodSource
    @ParameterizedTest
    void strictKeyExchange(Config config) throws Throwable {
        try (SSHClient client = sshd.getConnectedClient(config)) {
            client.authPublickey("sshj", "src/itest/resources/keyfiles/id_rsa_opensshv1");
            assertTrue(client.isAuthenticated());
        }
        List<String> keyExchangerLogs = getLogs("KeyExchanger");
        assertThat(keyExchangerLogs).contains(
            "Initiating key exchange",
            "Sending SSH_MSG_KEXINIT",
            "Received SSH_MSG_KEXINIT",
            "Enabling strict key exchange extension"
        );
        List<String> decoderLogs = getLogs("Decoder").stream()
            .map(log -> log.split(":")[0])
            .collect(Collectors.toList());
        assertThat(decoderLogs).startsWith(
            "Received packet #0",
            "Received packet #1",
            "Received packet #2",
            "Received packet #0",
            "Received packet #1",
            "Received packet #2",
            "Received packet #3"
        );
        List<String> encoderLogs = getLogs("Encoder").stream()
            .map(log -> log.split(":")[0])
            .collect(Collectors.toList());
        assertThat(encoderLogs).startsWith(
            "Encoding packet #0",
            "Encoding packet #1",
            "Encoding packet #2",
            "Encoding packet #0",
            "Encoding packet #1",
            "Encoding packet #2",
            "Encoding packet #3"
        );
    }

    private List<String> getLogs(String className) {
        return logWatcher.list.stream()
            .filter(event -> event.getLoggerName().endsWith(className))
            .map(ILoggingEvent::getFormattedMessage)
            .collect(Collectors.toList());
    }

    private static class HotLoopHeartbeater extends KeepAlive {

        HotLoopHeartbeater(ConnectionImpl conn) {
            super(conn, "sshj-Heartbeater");
        }

        @Override
        public boolean isEnabled() {
            return true;
        }

        @Override
        protected void doKeepAlive() throws TransportException {
            conn.getTransport().write(new SSHPacket(Message.IGNORE).putString(""));
        }

    }

}
