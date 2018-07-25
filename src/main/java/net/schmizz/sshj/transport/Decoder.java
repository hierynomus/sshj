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

import net.schmizz.sshj.common.*;
import net.schmizz.sshj.transport.cipher.Cipher;
import net.schmizz.sshj.transport.compression.Compression;
import net.schmizz.sshj.transport.mac.MAC;
import org.slf4j.Logger;

/**
 * Decodes packets from the SSH binary protocol per the current algorithms.
 */
final class Decoder
        extends Converter {

    private static final int MAX_PACKET_LEN = 256 * 1024;

    private final Logger log;

    /**
     * What we pass decoded packets to
     */
    private final SSHPacketHandler packetHandler;
    /**
     * Buffer where as-yet undecoded data lives
     */
    private final SSHPacket inputBuffer = new SSHPacket();
    /**
     * Used in case compression is active to store the uncompressed data
     */
    private final SSHPacket uncompressBuffer = new SSHPacket();
    /**
     * MAC result is stored here
     */
    private byte[] macResult;

    /**
     * -1 if packet length not yet been decoded, else the packet length
     */
    private int packetLength = -1;

    /**
     * How many bytes do we need, before a call to decode() can succeed at decoding at least packet length, OR the whole
     * packet?
     */
    private int needed = 8;

    Decoder(Transport packetHandler) {
        this.packetHandler = packetHandler;
        log = packetHandler.getConfig().getLoggerFactory().getLogger(getClass());
    }

    /**
     * Returns advised number of bytes that should be made available in decoderBuffer before the method should be called
     * again.
     *
     * @return number of bytes needed before further decoding possible
     */
    private int decode()
            throws SSHException {

        if (etm) {
            return decodeEtm();
        } else {
            return decodeMte();
        }
    }

    /**
     * Decode an Encrypt-Then-Mac packet.
     */
    private int decodeEtm() throws SSHException {
        int bytesNeeded;
        while (true) {
            if (packetLength == -1) {
                assert inputBuffer.rpos() == 0 : "buffer cleared";
                bytesNeeded = 4 - inputBuffer.available();
                if (bytesNeeded <= 0) {
                    // In Encrypt-Then-Mac, the packetlength is sent unencrypted.
                    packetLength = inputBuffer.readUInt32AsInt();
                    checkPacketLength(packetLength);
                } else {
                    // Needs more data
                    break;
                }
            } else {
                assert inputBuffer.rpos() == 4 : "packet length read";
                bytesNeeded = packetLength + mac.getBlockSize() - inputBuffer.available();
                if (bytesNeeded <= 0) {
                    seq = seq + 1 & 0xffffffffL;
                    checkMAC(inputBuffer.array());
                    decryptBuffer(4, packetLength);
                    inputBuffer.wpos(packetLength + 4 - inputBuffer.readByte());
                    final SSHPacket plain = usingCompression() ? decompressed() : inputBuffer;
                    if (log.isTraceEnabled()) {
                        log.trace("Received packet #{}: {}", seq, plain.printHex());
                    }
                    packetHandler.handle(plain.readMessageID(), plain); // Process the decoded packet
                    inputBuffer.clear();
                    packetLength = -1;
                } else {
                    // Needs more data
                    break;
                }
            }
        }
        return bytesNeeded;
    }

    /**
     * Decode a Mac-Then-Encrypt packet
     * @return
     * @throws SSHException
     */
    private int decodeMte() throws SSHException {
        int need;

        /* Decoding loop */
        for (; ; )

            if (packetLength == -1) { // Waiting for beginning of packet
                assert inputBuffer.rpos() == 0 : "buffer cleared";
                need = cipherSize - inputBuffer.available();
                if (need <= 0) {
                    packetLength = decryptLength();
                } else {
                    // Need more data
                    break;
                }
            } else {
                assert inputBuffer.rpos() == 4 : "packet length read";
                need = packetLength + (mac != null ? mac.getBlockSize() : 0) - inputBuffer.available();
                if (need <= 0) {
                    decryptBuffer(cipherSize, packetLength + 4 - cipherSize); // Decrypt the rest of the payload
                    seq = seq + 1 & 0xffffffffL;
                    if (mac != null) {
                        checkMAC(inputBuffer.array());
                    }
                    // Exclude the padding & MAC
                    inputBuffer.wpos(packetLength + 4 - inputBuffer.readByte());
                    final SSHPacket plain = usingCompression() ? decompressed() : inputBuffer;
                    if (log.isTraceEnabled()) {
                        log.trace("Received packet #{}: {}", seq, plain.printHex());
                    }
                    packetHandler.handle(plain.readMessageID(), plain); // Process the decoded packet
                    inputBuffer.clear();
                    packetLength = -1;
                } else {
                    // Need more data
                    break;
                }
            }

        return need;
    }

    private void checkMAC(final byte[] data)
            throws TransportException {
        mac.update(seq); // seq num
        mac.update(data, 0, packetLength + 4); // packetLength+4 = entire packet w/o mac
        mac.doFinal(macResult, 0); // compute
        // Check against the received MAC
        if (!ByteArrayUtils.equals(macResult, 0, data, packetLength + 4, mac.getBlockSize())) {
            throw new TransportException(DisconnectReason.MAC_ERROR, "MAC Error");
        }
    }

    private SSHPacket decompressed()
            throws TransportException {
        uncompressBuffer.clear();
        compression.uncompress(inputBuffer, uncompressBuffer);
        return uncompressBuffer;
    }

    private int decryptLength()
            throws TransportException {
        decryptBuffer(0, cipherSize);

        final int len; // Read packet length
        try {
            len = inputBuffer.readUInt32AsInt();
        } catch (Buffer.BufferException be) {
            throw new TransportException(be);
        }

        checkPacketLength(len);

        return len;
    }

    private void decryptBuffer(int offset, int length) {
        cipher.update(inputBuffer.array(), offset, length);
    }

    private void checkPacketLength(int len) throws TransportException {
        if (len < 5 || len > MAX_PACKET_LEN) { // Check packet length validity
            log.error("Error decoding packet (invalid length) {}", inputBuffer.printHex());
            throw new TransportException(DisconnectReason.PROTOCOL_ERROR, "invalid packet length: " + len);
        }
    }

//    private void decryptPayload(final byte[] data, int offset, int length) {
//        cipher.update(data, cipherSize, packetLength + 4 - cipherSize);
//    }

    /**
     * Adds {@code len} bytes from {@code b} to the decoder buffer. When a packet has been successfully decoded, hooks
     * in to {@link SSHPacketHandler#handle} of the {@link SSHPacketHandler} this decoder was initialized with.
     * <p/>
     * Returns the number of bytes expected in the next call in order to decode the packet length, and if the packet
     * length has already been decoded; to decode the payload. This number is accurate and should be taken to heart.
     */
    int received(byte[] b, int len)
            throws SSHException {
        inputBuffer.putRawBytes(b, 0, len);
        if (needed <= len)
            needed = decode();
        else
            needed -= len;
        return needed;
    }

    @Override
    void setAlgorithms(Cipher cipher, MAC mac, Compression compression) {
        super.setAlgorithms(cipher, mac, compression);
        macResult = new byte[mac.getBlockSize()];
    }

    @Override
    Compression.Mode getCompressionType() {
        return Compression.Mode.INFLATE;
    }

    int getMaxPacketLength() {
        return MAX_PACKET_LEN;
    }

}
