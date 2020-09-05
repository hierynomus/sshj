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

import com.hierynomus.sshj.transport.cipher.GcmCiphers;
import net.schmizz.sshj.Config;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.common.LoggerFactory;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.transport.cipher.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;
import java.security.Security;

import static org.junit.Assert.assertArrayEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class DecoderDecryptGcmCipherSshPacketTest {

    private int PACKET_LENGTH;

    private byte[] key;

    private byte[] iv;

    private byte[] data;

    private byte[] decrypted;

    private Decoder decoder;

    @Before
    public void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        ClassLoader classLoader = DecoderDecryptGcmCipherSshPacketTest.class.getClassLoader();
        iv = IOUtils.readFully(classLoader.getResourceAsStream("ssh-packets/gcm/mina-sshd/s2c.iv.bin" )).toByteArray();
        key = IOUtils.readFully(classLoader.getResourceAsStream("ssh-packets/gcm/mina-sshd/s2c.key.bin" )).toByteArray();
        data = IOUtils.readFully(classLoader.getResourceAsStream("ssh-packets/gcm/mina-sshd/client.receive.1.bin" )).toByteArray();

        SSHPacket packet = new SSHPacket(IOUtils.readFully(classLoader.getResourceAsStream("ssh-packets/gcm/mina-sshd/client.decrypted.1.bin" )).toByteArray());
        PACKET_LENGTH = packet.readUInt32AsInt();
        decrypted = new byte[PACKET_LENGTH];
        System.arraycopy(packet.array(), 0, decrypted, 0, PACKET_LENGTH);

        Config config = mock(Config.class);
        Transport transport = mock(Transport.class);
        when(transport.getConfig()).thenReturn(config);
        when(config.getLoggerFactory()).thenReturn(LoggerFactory.DEFAULT);
        doAnswer(invocation -> {
            SSHPacket p = invocation.getArgument(1);
            byte[] verify = new byte[PACKET_LENGTH];
            System.arraycopy(p.array(), 0, verify, 0, PACKET_LENGTH);
            assertArrayEquals(decrypted, verify);
            return null;
        }).when(transport).handle(any(), any());

        decoder = new Decoder(transport);
        Cipher cipher = GcmCiphers.AES128GCM().create();
        cipher.init(Cipher.Mode.Decrypt, key, iv);
        decoder.setAlgorithms(cipher, null, null);
    }

    @Test
    public void testDecodeInOneGo() throws SSHException {
        decoder.received(data, data.length);
    }

    @Test
    public void testDecodeInConstantChunks() throws SSHException {
        int chunkSize = 16;
        int remain = PACKET_LENGTH;
        int pos = 0;
        while(remain >= 0) {
            byte[] chunk = new byte[chunkSize];
            System.arraycopy(data, pos, chunk, 0, chunkSize);
            decoder.received(chunk, chunk.length);
            pos += chunkSize;
            remain -= chunkSize;
        }
    }

    @Test
    public void testDecodeInRandomChunks() throws SSHException {
        SecureRandom sr = new SecureRandom();
        int remain = PACKET_LENGTH;
        int pos = 0;
        while(remain >= 0) {
            int chunkSize = sr.nextInt(10);
            if (chunkSize - remain < 0)
                chunkSize = remain;
            byte[] chunk = new byte[chunkSize];
            System.arraycopy(data, pos, chunk, 0, chunkSize);
            decoder.received(chunk, chunk.length);
            pos += chunkSize;
            remain -= chunkSize;
        }
    }
}
