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
package net.schmizz.sshj.transport.mac;

/**
 * Message Authentication Code for use in SSH. It usually wraps a javax.crypto.Mac class.
 */
public interface MAC {

    byte[] doFinal();

    byte[] doFinal(byte[] input);

    void doFinal(byte[] buf, int offset);

    int getBlockSize();

    void init(byte[] key);

    void update(byte[] foo);

    void update(byte[] foo, int start, int len);

    void update(long foo);

    /**
     * Indicates that an Encrypt-Then-Mac algorithm was selected.
     * <p>
     * This has the following implementation details.
     * 1.5 transport: Protocol 2 Encrypt-then-MAC MAC algorithms
     * <p>
     * OpenSSH supports MAC algorithms, whose names contain "-etm", that
     * perform the calculations in a different order to that defined in RFC
     * 4253. These variants use the so-called "encrypt then MAC" ordering,
     * calculating the MAC over the packet ciphertext rather than the
     * plaintext. This ordering closes a security flaw in the SSH transport
     * protocol, where decryption of unauthenticated ciphertext provided a
     * "decryption oracle" that could, in conjunction with cipher flaws, reveal
     * session plaintext.
     * <p>
     * Specifically, the "-etm" MAC algorithms modify the transport protocol
     * to calculate the MAC over the packet ciphertext and to send the packet
     * length unencrypted. This is necessary for the transport to obtain the
     * length of the packet and location of the MAC tag so that it may be
     * verified without decrypting unauthenticated data.
     * <p>
     * As such, the MAC covers:
     * <p>
     * mac = MAC(key, sequence_number || packet_length || encrypted_packet)
     * <p>
     * where "packet_length" is encoded as a uint32 and "encrypted_packet"
     * contains:
     * <p>
     * byte      padding_length
     * byte[n1]  payload; n1 = packet_length - padding_length - 1
     * byte[n2] random padding; n2 = padding_length
     *
     * @return Whether the MAC algorithm is an Encrypt-Then-Mac algorithm
     */
    boolean isEtm();
}
