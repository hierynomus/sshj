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
package com.hierynomus.sshj.transport.cipher;

import static com.hierynomus.sshj.transport.cipher.BlockCiphers.CIPHER_BLOCK_CHAINING_MODE;
import static com.hierynomus.sshj.transport.cipher.BlockCiphers.COUNTER_MODE;

/**
 * Set of Block Ciphers that are (not yet) part of any of the official RFCs for SSH, but
 * that are either supported by other SSH implementations, or are being pushed for to be
 * included in a new RFC.
 *
 * - http://tools.ietf.org/id/draft-kanno-secsh-camellia-01.txt
 */
@SuppressWarnings("PMD.MethodNamingConventions")
public class ExtendedBlockCiphers {
    public static BlockCiphers.Factory Camellia128CTR() {
        return new BlockCiphers.Factory(16, 128, "camellia128-ctr", "Camellia", COUNTER_MODE);
    }
    public static BlockCiphers.Factory Camellia128CTROpenSSHOrg() {
        return new BlockCiphers.Factory(16, 128, "camellia128-ctr@openssh.org", "Camellia", COUNTER_MODE);
    }
    public static BlockCiphers.Factory Camellia192CTR() {
        return new BlockCiphers.Factory(16, 192, "camellia192-ctr", "Camellia", COUNTER_MODE);
    }
    public static BlockCiphers.Factory Camellia192CTROpenSSHOrg() {
        return new BlockCiphers.Factory(16, 192, "camellia192-ctr@openssh.org", "Camellia", COUNTER_MODE);
    }
    public static BlockCiphers.Factory Camellia256CTR() {
        return new BlockCiphers.Factory(16, 256, "camellia256-ctr", "Camellia", COUNTER_MODE);
    }
    public static BlockCiphers.Factory Camellia256CTROpenSSHOrg() {
        return new BlockCiphers.Factory(16, 256, "camellia256-ctr@openssh.org", "Camellia", COUNTER_MODE);
    }
    public static BlockCiphers.Factory Camellia128CBC() {
        return new BlockCiphers.Factory(16, 128, "camellia128-cbc", "Camellia", CIPHER_BLOCK_CHAINING_MODE);
    }
    public static BlockCiphers.Factory Camellia128CBCOpenSSHOrg() {
        return new BlockCiphers.Factory(16, 128, "camellia128-cbc@openssh.org", "Camellia", CIPHER_BLOCK_CHAINING_MODE);
    }
    public static BlockCiphers.Factory Camellia192CBC() {
        return new BlockCiphers.Factory(16, 192, "camellia192-cbc", "Camellia", CIPHER_BLOCK_CHAINING_MODE);
    }
    public static BlockCiphers.Factory Camellia192CBCOpenSSHOrg() {
        return new BlockCiphers.Factory(16, 192, "camellia192-cbc@openssh.org", "Camellia", CIPHER_BLOCK_CHAINING_MODE);
    }
    public static BlockCiphers.Factory Camellia256CBC() {
        return new BlockCiphers.Factory(16, 256, "camellia256-cbc", "Camellia", CIPHER_BLOCK_CHAINING_MODE);
    }
    public static BlockCiphers.Factory Camellia256CBCOpenSSHOrg() {
        return new BlockCiphers.Factory(16, 256, "camellia256-cbc@openssh.org", "Camellia", CIPHER_BLOCK_CHAINING_MODE);
    }


}
