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
package com.hierynomus.sshj.transport;

import com.hierynomus.sshj.transport.cipher.GcmCiphers;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.transport.cipher.Cipher;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Unit test to decrypt SSH traffic with OpenSSH and Apache Mina SSHD (master) using AES-GCM ciphers, for verifying
 * cipher behaviour.
 */

public class GcmCipherDecryptSshPacketTest {

    public static Stream<Arguments> sets() {
        return Stream.of(Arguments.of("mina-sshd", 3), Arguments.of("openssh", 4));
    }

    @ParameterizedTest
    @MethodSource("sets")
    public void testDecryptPacket(String ssh, int nr) throws Exception {
        ClassLoader classLoader = getClass().getClassLoader();
        byte[] iv = IOUtils.readFully(classLoader.getResourceAsStream("ssh-packets/gcm/" + ssh + "/s2c.iv.bin"))
                .toByteArray();
        byte[] key = IOUtils.readFully(classLoader.getResourceAsStream("ssh-packets/gcm/" + ssh + "/s2c.key.bin"))
                .toByteArray();
        Cipher cipher = GcmCiphers.AES128GCM().create();
        cipher.init(Cipher.Mode.Decrypt, key, iv);
        for (int i = 1; i <= nr; i++) {
            byte[] data = IOUtils
                    .readFully(classLoader
                            .getResourceAsStream("ssh-packets/gcm/" + ssh + "/client.receive." + i + ".bin"))
                    .toByteArray();
            SSHPacket inputBuffer = new SSHPacket(data);
            cipher.updateAAD(inputBuffer.array(), 0, 4);
            int size = inputBuffer.readUInt32AsInt();
            cipher.update(inputBuffer.array(), 4, size);
            byte[] expected = IOUtils
                    .readFully(classLoader
                            .getResourceAsStream("ssh-packets/gcm/" + ssh + "/client.decrypted." + i + ".bin"))
                    .toByteArray();
            assertArrayEquals(Arrays.copyOfRange(expected, 0, size + 4),
                    Arrays.copyOfRange(inputBuffer.array(), 0, size + 4));
        }
    }
}
