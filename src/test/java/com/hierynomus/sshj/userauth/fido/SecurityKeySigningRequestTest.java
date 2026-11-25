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
package com.hierynomus.sshj.userauth.fido;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;

public class SecurityKeySigningRequestTest {

    private static final byte[] DATA = "data to sign".getBytes(StandardCharsets.UTF_8);
    private static final byte[] KEY_HANDLE = {1, 2, 3};

    @Test
    public void exposesTheDataAndItsHash() throws Exception {
        final SecurityKeySigningRequest request = SecurityKeySigningRequest.forData(
                "sk-ssh-ed25519@openssh.com", "ssh:", KEY_HANDLE, DATA, (byte) 0x05);

        assertArrayEquals(DATA, request.getData());
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(DATA), request.getChallenge(),
                "the challenge is the SHA-256 of the data: the WebAuthn client-data hash");
        assertEquals("sk-ssh-ed25519@openssh.com", request.getKeyTypeName());
        assertEquals("ssh:", request.getApplication());
        assertArrayEquals(KEY_HANDLE, request.getKeyHandle());
        assertEquals((byte) 0x05, request.getMinFlags());
    }

    @Test
    public void dataIsProtectedFromChangesByTheCallerAndTheReader() {
        final byte[] data = DATA.clone();
        final SecurityKeySigningRequest request = SecurityKeySigningRequest.forData(
                "sk-ssh-ed25519@openssh.com", "ssh:", KEY_HANDLE, data, (byte) 0);

        data[0] ^= 0x01; // the caller changes its array after creating the request
        final byte[] first = request.getData();
        first[1] ^= 0x01; // a reader changes what it was handed

        assertArrayEquals(DATA, request.getData());
        assertNotSame(request.getData(), request.getData());
    }

    @Test
    @SuppressWarnings("deprecation")
    public void challengeOnlyRequestHasNoData() {
        final byte[] challenge = {9, 8, 7};
        final SecurityKeySigningRequest request = new SecurityKeySigningRequest(
                "sk-ecdsa-sha2-nistp256@openssh.com", "ssh:", KEY_HANDLE, challenge, (byte) 0);

        assertArrayEquals(challenge, request.getChallenge());
        assertNull(request.getData(), "a request built from only a challenge cannot supply the data");
    }
}
