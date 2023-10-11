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
package net.schmizz.sshj.sftp;

import net.schmizz.sshj.common.LoggerFactory;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.connection.channel.direct.Session.Subsystem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.DataOutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class PacketReaderTest {

    private DataOutputStream dataout;
    private PacketReader reader;

    @BeforeEach
    public void setUp() throws Exception {
        PipedOutputStream pipedout = new PipedOutputStream();
        PipedInputStream pipedin = new PipedInputStream(pipedout);
        dataout = new DataOutputStream(pipedout);

        SFTPEngine engine = Mockito.mock(SFTPEngine.class);
        Subsystem subsystem = Mockito.mock(Subsystem.class);
        Mockito.when(engine.getLoggerFactory()).thenReturn(LoggerFactory.DEFAULT);
        Mockito.when(engine.getSubsystem()).thenReturn(subsystem);
        Mockito.when(subsystem.getInputStream()).thenReturn(pipedin);

        reader = new PacketReader(engine);
    }

    // FIXME What is the byte format for the size? Big endian? Little endian?
    @Test
    public void shouldReadPacket() throws Exception {
        byte[] bytes = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        dataout.writeInt(10);
        dataout.write(bytes);
        dataout.flush();

        SFTPPacket<Response> packet = reader.readPacket();
        assertEquals(packet.available(), 10);
        assertTrue(Arrays.equals(bytes, subArray(packet.array(), 0, 10)), "actual=" + Arrays.toString(packet.array()));
    }

    @Test
    public void shouldFailWhenPacketLengthTooLarge() throws Exception {
        dataout.writeInt(Integer.MAX_VALUE);
        dataout.flush();

        try {
            reader.readPacket();
            fail("Should have failed to read packet of size " + Integer.MAX_VALUE);
        } catch (SSHException e) {
            e.printStackTrace();
            // success; indicated packet size was too large
        }
    }

    private byte[] subArray(byte[] source, int startIndex, int length) {
        byte[] result = new byte[length];
        System.arraycopy(source, startIndex, result, 0, length);
        return result;
    }
}
