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
package net.schmizz.sshj.connection.channel;

import net.schmizz.concurrent.Event;
import net.schmizz.concurrent.ExceptionChainer;
import net.schmizz.sshj.common.LoggerFactory;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.TimeUnit;

import static org.mockito.Mockito.*;

public class SocketStreamCopyMonitorTest {

    @Test
    public void shouldNotCloseChannelIfOnlyFirstEventSet() throws Exception {
        final Channel channel = mock(Channel.class);
        final Socket socket = mock(Socket.class);
        final Event<IOException> xEvent = createEvent();
        final Event<IOException> yEvent = createEvent();
        SocketStreamCopyMonitor.monitor(1, TimeUnit.MILLISECONDS, xEvent, yEvent, channel, socket);

        xEvent.set();

        waitForMonitorThreadToCloseTheChannel();

        verify(channel, never()).close();
    }

    @Test
    public void shouldNotCloseChannelIfOnlySecondEventSet() throws Exception {
        final Channel channel = mock(Channel.class);
        final Socket socket = mock(Socket.class);
        final Event<IOException> xEvent = createEvent();
        final Event<IOException> yEvent = createEvent();
        SocketStreamCopyMonitor.monitor(1, TimeUnit.MILLISECONDS, xEvent, yEvent, channel, socket);

        yEvent.set();

        waitForMonitorThreadToCloseTheChannel();

        verify(channel, never()).close();
    }

    @Test
    public void shouldCloseChannelIfBothEventsSet() throws Exception {
        final Channel channel = mock(Channel.class);
        final Socket socket = mock(Socket.class);
        final Event<IOException> xEvent = createEvent();
        final Event<IOException> yEvent = createEvent();
        SocketStreamCopyMonitor.monitor(1, TimeUnit.MILLISECONDS, xEvent, yEvent, channel, socket);

        xEvent.set();
        yEvent.set();

        waitForMonitorThreadToCloseTheChannel();

        verify(channel, times(1)).close();
    }

    private void waitForMonitorThreadToCloseTheChannel() throws InterruptedException {
        Thread.sleep(50);
    }

    private Event<IOException> createEvent() {
        return new Event<IOException>("event", new ExceptionChainer<IOException>() {
            @Override
            public IOException chain(Throwable t) {
                return new IOException(t);
            }
        }, LoggerFactory.DEFAULT);
    }
}
