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

import net.schmizz.sshj.transport.cipher.Cipher;
import net.schmizz.sshj.transport.cipher.NoneCipher;
import net.schmizz.sshj.transport.compression.Compression;
import net.schmizz.sshj.transport.mac.MAC;

/**
 * Base class for {@link Encoder} and {@link Decoder}.
 * <p/>
 * From RFC 4253, p. 6
 * <p/>
 * <pre>
 *    Each packet is in the following format:
 *
 *       uint32    packet_length
 *       byte      padding_length
 *       byte[n1]  payload; n1 = packet_length - padding_length - 1
 *       byte[n2]  random padding; n2 = padding_length
 *       byte[m]   mac (Message Authentication Code - MAC); m = mac_length
 * </pre>
 */
abstract class Converter {

    protected Cipher cipher = new NoneCipher();
    protected MAC mac = null;
    protected Compression compression = null;

    protected int cipherSize = 8;
    protected long seq = -1;
    protected boolean authed;
    protected boolean etm;
    protected boolean authMode;

    long getSequenceNumber() {
        return seq;
    }

    void setAlgorithms(Cipher cipher, MAC mac, Compression compression) {
        this.cipher = cipher;
        this.mac = mac;
        this.compression = compression;
        if (compression != null)
            compression.init(getCompressionType());
        this.cipherSize = cipher.getIVSize();
        this.etm = this.mac != null && mac.isEtm();
        if(cipher.getAuthenticationTagSize() > 0) {
            this.cipherSize = cipher.getAuthenticationTagSize();
            this.authMode = true;
        }
    }

    void setAuthenticated() {
        this.authed = true;
    }

    boolean usingCompression() {
        return compression != null && (authed || !compression.isDelayed());
    }

    abstract Compression.Mode getCompressionType();

}