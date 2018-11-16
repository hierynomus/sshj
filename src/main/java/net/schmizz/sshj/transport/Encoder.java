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

import net.schmizz.sshj.common.LoggerFactory;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.transport.cipher.Cipher;
import net.schmizz.sshj.transport.compression.Compression;
import net.schmizz.sshj.transport.mac.MAC;
import net.schmizz.sshj.transport.random.Random;
import org.slf4j.Logger;

import java.util.concurrent.locks.Lock;

/** Encodes packets into the SSH binary protocol per the current algorithms. */
final class Encoder
        extends Converter {

    private final Logger log;
    private final Random prng;
    private final Lock encodeLock;

    Encoder(Random prng, Lock encodeLock, LoggerFactory loggerFactory) {
        this.prng = prng;
        this.encodeLock = encodeLock;
        log = loggerFactory.getLogger(getClass());
    }

    private void compress(SSHPacket buffer) {
        compression.compress(buffer);
    }

    private void putMAC(SSHPacket buffer, int startOfPacket, int endOfPadding) {
        buffer.wpos(endOfPadding + mac.getBlockSize());
        mac.update(seq);
        mac.update(buffer.array(), startOfPacket, endOfPadding);
        mac.doFinal(buffer.array(), endOfPadding);
    }

    /**
     * Encode a buffer into the SSH binary protocol per the current algorithms.
     *
     * @param buffer the buffer to encode
     *
     * @return the sequence no. of encoded packet
     *
     * @throws TransportException
     */
    long encode(SSHPacket buffer) {
        encodeLock.lock();
        try {
            if (log.isTraceEnabled()) {
                // Add +1 to seq as we log before actually incrementing the sequence.
                log.trace("Encoding packet #{}: {}", seq + 1, buffer.printHex());
            }

            if (usingCompression()) {
                compress(buffer);
            }

            final int payloadSize = buffer.available();
            int lengthWithoutPadding;
            if (etm) {
                // in Encrypt-Then-Mac mode, the length field is not encrypted, so we should keep it out of the
                // padding length calculation
                lengthWithoutPadding = 1 + payloadSize; // padLength (1 byte) + payload
            } else {
                lengthWithoutPadding = 4 + 1 + payloadSize; // packetLength (4 bytes) + padLength (1 byte) + payload
            }

            // Compute padding length
            int padLen = cipherSize - (lengthWithoutPadding % cipherSize);
            if (padLen < 4) {
                padLen += cipherSize;
            }

            final int startOfPacket = buffer.rpos() - 5;
            int packetLen = 1 + payloadSize + padLen; // packetLength = padLen (1 byte) + payload + padding

            if (packetLen < 16) {
                padLen += cipherSize;
                packetLen = 1 + payloadSize + padLen;
            }

            final int endOfPadding = startOfPacket + 4 + packetLen;

            // Put packet header
            buffer.wpos(startOfPacket);
            buffer.putUInt32(packetLen);
            buffer.putByte((byte) padLen);
            // Now wpos will mark end of padding
            buffer.wpos(endOfPadding);

            // Fill padding
            prng.fill(buffer.array(), endOfPadding - padLen, padLen);

            seq = seq + 1 & 0xffffffffL;

            if (etm) {
                cipher.update(buffer.array(), startOfPacket + 4, packetLen);
                putMAC(buffer, startOfPacket, endOfPadding);
            } else {
                if (mac != null) {
                    putMAC(buffer, startOfPacket, endOfPadding);
                }

                cipher.update(buffer.array(), startOfPacket, 4 + packetLen);
            }
            buffer.rpos(startOfPacket); // Make ready-to-read

            return seq;
        } finally {
            encodeLock.unlock();
        }
    }

    @Override
    void setAlgorithms(Cipher cipher, MAC mac, Compression compression) {
        encodeLock.lock();
        try {
            super.setAlgorithms(cipher, mac, compression);
        } finally {
            encodeLock.unlock();
        }
    }

    @Override
    void setAuthenticated() {
        encodeLock.lock();
        try {
            super.setAuthenticated();
        } finally {
            encodeLock.unlock();
        }
    }

    @Override
    Compression.Mode getCompressionType() {
        return Compression.Mode.DEFLATE;
    }

}
