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

import com.hierynomus.sshj.signature.SignatureSkEcdsa;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.signature.Signature;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the factories that turn what an OpenSSH security key middleware returns into a
 * {@link SecurityKeySignatureData}, using a {@link SoftwareSecurityKeyMiddleware} for the real thing.
 */
public class SecurityKeySignatureDataTest {

    private static final String APPLICATION = "ssh:";
    private static final byte[] KEY_HANDLE = {1, 2, 3};
    private static final byte[] MESSAGE = "message".getBytes(StandardCharsets.UTF_8);

    @Test
    public void ecdsaKeepsTheFlagsAndCounter() {
        final SecurityKeySignatureData data = SecurityKeySignatureData.ecdsa((byte) 0x05, 0xFFFFFFFEL, new byte[] {1}, new byte[] {2});

        assertEquals((byte) 0x05, data.getFlags());
        assertEquals(0xFFFFFFFEL, data.getCounter());
    }

    @Test
    public void ecdsaEncodesRAndSAsAnAsn1Sequence() {
        final SecurityKeySignatureData data = SecurityKeySignatureData.ecdsa((byte) 0, 0, new byte[] {0x01}, new byte[] {0x02});

        // SEQUENCE { INTEGER 1, INTEGER 2 }
        assertArrayEquals(new byte[] {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}, data.getSignature());
    }

    @Test
    public void ecdsaTreatsRAndSAsUnsignedSoAHighBitGetsASignByte() {
        final byte[] r = new byte[32];
        Arrays.fill(r, (byte) 0xFF); // top bit set: a signed reading would make it negative
        final SecurityKeySignatureData data = SecurityKeySignatureData.ecdsa((byte) 0, 0, r, new byte[] {0x7F});

        final BigInteger[] parsed = parse(data);
        assertEquals(new BigInteger(1, r), parsed[0]);
        assertEquals(BigInteger.valueOf(0x7F), parsed[1]);
    }

    @Test
    public void ecdsaAcceptsValuesWithLeadingZerosAlreadyTrimmed() {
        // A middleware reports each value with as many bytes as it needs, not as a fixed 32.
        final SecurityKeySignatureData data = SecurityKeySignatureData.ecdsa((byte) 0, 0, new byte[] {0x12, 0x34}, new byte[] {0x56});

        final BigInteger[] parsed = parse(data);
        assertEquals(BigInteger.valueOf(0x1234), parsed[0]);
        assertEquals(BigInteger.valueOf(0x56), parsed[1]);
    }

    @Test
    public void ecdsaRejectsMissingValues() {
        assertThrows(IllegalArgumentException.class, () -> SecurityKeySignatureData.ecdsa((byte) 0, 0, null, new byte[] {1}));
        assertThrows(IllegalArgumentException.class, () -> SecurityKeySignatureData.ecdsa((byte) 0, 0, new byte[] {1}, null));
        assertThrows(IllegalArgumentException.class, () -> SecurityKeySignatureData.ecdsa((byte) 0, 0, new byte[0], new byte[] {1}));
        assertThrows(IllegalArgumentException.class, () -> SecurityKeySignatureData.ecdsa((byte) 0, 0, new byte[] {1}, new byte[0]));
    }

    /**
     * The result must be what sshj's own signature expects of a device, whatever the values: sign with a
     * software middleware many times, so that values with a high bit and with leading zeros all occur,
     * and check that every one verifies.
     */
    @Test
    public void ecdsaFromAMiddlewareResponseAlwaysVerifies() throws Exception {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        final KeyPair credential = kpg.generateKeyPair();
        final SoftwareSecurityKeyMiddleware middleware = new SoftwareSecurityKeyMiddleware(false, credential, KEY_HANDLE);
        final SecurityKeyPublicKey publicKey = new SecurityKeyPublicKey(credential.getPublic(), APPLICATION);

        for (int i = 0; i < 200; i++) {
            final SoftwareSecurityKeyMiddleware.Response response = middleware.sign(MESSAGE, APPLICATION, KEY_HANDLE, (byte) 0);
            final SecurityKeySignatureData data = SecurityKeySignatureData.ecdsa(
                    response.getFlags(), response.getCounter(), response.getSigR(), response.getSigS());

            final SecurityKeyPrivateKey privateKey = new SecurityKeyPrivateKey(KeyType.SK_ECDSA.toString(), publicKey, (byte) 0,
                    KEY_HANDLE, request -> data);
            final Signature signing = new SignatureSkEcdsa();
            signing.initSign(privateKey);
            signing.update(MESSAGE);
            final byte[] wireSignature = signing.encode(signing.sign());

            final Signature verifying = new SignatureSkEcdsa();
            verifying.initVerify(publicKey);
            verifying.update(MESSAGE);
            assertTrue(verifying.verify(wireSignature), "signature " + i + " should verify");
        }
    }

    @Test
    public void ed25519KeepsTheSignatureFlagsAndCounter() {
        final byte[] signature = new byte[64];
        Arrays.fill(signature, (byte) 0xAB);

        final SecurityKeySignatureData data = SecurityKeySignatureData.ed25519((byte) 0x01, 7L, signature);

        assertArrayEquals(signature, data.getSignature());
        assertEquals((byte) 0x01, data.getFlags());
        assertEquals(7L, data.getCounter());
    }

    @Test
    public void ed25519DoesNotShareTheCallersArray() {
        final byte[] signature = new byte[64];

        final SecurityKeySignatureData data = SecurityKeySignatureData.ed25519((byte) 0, 0, signature);
        signature[0] = 1;

        assertEquals(0, data.getSignature()[0]);
        assertNotSame(data.getSignature(), data.getSignature());
    }

    @Test
    public void ed25519RejectsASignatureOfTheWrongLength() {
        assertThrows(IllegalArgumentException.class, () -> SecurityKeySignatureData.ed25519((byte) 0, 0, null));
        assertThrows(IllegalArgumentException.class, () -> SecurityKeySignatureData.ed25519((byte) 0, 0, new byte[63]));
        assertThrows(IllegalArgumentException.class, () -> SecurityKeySignatureData.ed25519((byte) 0, 0, new byte[65]));
    }

    /** Reads r and s back out of the data through the signature class that consumes the DER form. */
    private static BigInteger[] parse(SecurityKeySignatureData data) {
        try {
            final byte[] ssh = new SignatureSkEcdsaAccess().toSsh(data.getSignature());
            final Buffer.PlainBuffer buf = new Buffer.PlainBuffer(ssh);
            return new BigInteger[] {buf.readMPInt(), buf.readMPInt()};
        } catch (Buffer.BufferException e) {
            throw new AssertionError(e);
        }
    }

    /** Exposes the protected conversion from the device's DER signature to the SSH {@code r}, {@code s} mpints. */
    private static final class SignatureSkEcdsaAccess extends SignatureSkEcdsa {
        byte[] toSsh(byte[] der) {
            return deviceSignatureToSsh(der);
        }
    }
}
