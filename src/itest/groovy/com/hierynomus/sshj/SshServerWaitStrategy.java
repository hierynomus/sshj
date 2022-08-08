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

import org.testcontainers.containers.wait.strategy.WaitStrategy;
import org.testcontainers.containers.wait.strategy.WaitStrategyTarget;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;

/**
 * A wait strategy designed for {@link SshdContainer} to wait until the SSH server is ready, to avoid races when a test
 * tries to connect to a server before the server has started.
 */
public class SshServerWaitStrategy implements WaitStrategy {
    private Duration startupTimeout = Duration.ofMinutes(1);

    @Override
    public void waitUntilReady(WaitStrategyTarget waitStrategyTarget) {
        long expectedEnd = System.nanoTime() + startupTimeout.toNanos();
        while (waitStrategyTarget.isRunning()) {
            long attemptStart = System.nanoTime();
            IOException error = null;
            byte[] buffer = new byte[7];
            try (Socket socket = new Socket()) {
                socket.setSoTimeout(500);
                socket.connect(new InetSocketAddress(
                        waitStrategyTarget.getHost(), waitStrategyTarget.getFirstMappedPort()));
                // Haven't seen any SSH server that sends the version in two or more packets.
                //noinspection ResultOfMethodCallIgnored
                socket.getInputStream().read(buffer);
                if (!Arrays.equals(buffer, "SSH-2.0".getBytes(StandardCharsets.UTF_8))) {
                    error = new IOException("The version message doesn't look like an SSH server version");
                }
            } catch (IOException err) {
                error = err;
            }

            if (error == null) {
                break;
            } else if (System.nanoTime() >= expectedEnd) {
                throw new RuntimeException(error);
            }

            try {
                //noinspection BusyWait
                Thread.sleep(Math.max(0L, 500L - (System.nanoTime() - attemptStart) / 1_000_000));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    @Override
    public WaitStrategy withStartupTimeout(Duration startupTimeout) {
        this.startupTimeout = startupTimeout;
        return this;
    }
}
