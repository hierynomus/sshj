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
package com.hierynomus.sshj;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.hierynomus.sshj.SshdContainer.SshdConfigBuilder;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.connection.channel.direct.Session;

import static org.assertj.core.api.Assertions.*;

@Testcontainers
public class ManyChannelsTest {
    @Container
    private static final SshdContainer sshd = new SshdContainer(SshdContainer.Builder.defaultBuilder()
            .withSshdConfig(SshdConfigBuilder.defaultBuilder().with("MaxSessions", "200")).withAllKeys());

    @Test
    public void shouldWorkWithManyChannelsWithoutNoExistentChannelError_GH805() throws Throwable {
        try (SSHClient client = sshd.getConnectedClient()) {
            client.authPublickey("sshj", "src/test/resources/id_rsa");

            List<Future<Exception>> futures = new ArrayList<>();
            ExecutorService executorService = Executors.newCachedThreadPool();

            for (int i = 0; i < 20; i++) {
                futures.add(executorService.submit(() -> {
                    try {
                        for (int j = 0; j < 10; j++) {
                            try (Session sshSession = client.startSession()) {
                                try (Session.Command sshCommand = sshSession.exec("ls -la")) {
                                    IOUtils.readFully(sshCommand.getInputStream()).toString();
                                }
                            }
                        }
                    } catch (Exception e) {
                        return e;
                    }
                    return null;
                }));
            }

            executorService.shutdown();
            executorService.awaitTermination(1, TimeUnit.DAYS);

            assertThat(futures).allSatisfy(future -> assertThat(future.get()).isNull());
        }
    }
}
