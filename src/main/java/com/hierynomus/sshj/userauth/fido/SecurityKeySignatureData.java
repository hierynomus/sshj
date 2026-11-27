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

import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.encodingrules.der.DEREncoder;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.primitive.ASN1Integer;
import net.schmizz.sshj.common.SSHRuntimeException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * The result of a {@link SecurityKeySigner} assertion: what the authenticator reported back.
 */
public class SecurityKeySignatureData {

    private static final int ED25519_SIGNATURE_LENGTH = 64;

    private final byte flags;
    private final long counter;
    private final byte[] signature;

    /**
     * @param flags     the authenticator data flags the device returned (user-presence, user-verified, ...)
     * @param counter   the signature counter the device returned (an unsigned 32-bit value)
     * @param signature the raw signature the device produced: an ASN.1 DER ECDSA signature for
     *                  {@code sk-ecdsa-sha2-nistp256@openssh.com}, or the raw 64-byte Ed25519
     *                  signature for {@code sk-ssh-ed25519@openssh.com}
     */
    public SecurityKeySignatureData(byte flags, long counter, byte[] signature) {
        this.flags = flags;
        this.counter = counter;
        this.signature = signature;
    }

    /**
     * Creates the result for an {@code sk-ecdsa-sha2-nistp256@openssh.com} assertion from the separate
     * {@code r} and {@code s} values that an OpenSSH security key middleware reports ({@code sig_r} and
     * {@code sig_s} in {@code struct sk_sign_response}), encoding them as the ASN.1 DER signature the
     * constructor expects.
     *
     * @param flags   the authenticator data flags the device returned
     * @param counter the signature counter the device returned (an unsigned 32-bit value)
     * @param r       the {@code r} value, an unsigned big-endian integer
     * @param s       the {@code s} value, an unsigned big-endian integer
     * @return the signature data
     * @throws IllegalArgumentException if {@code r} or {@code s} is missing or empty
     */
    public static SecurityKeySignatureData ecdsa(byte flags, long counter, byte[] r, byte[] s) {
        requireValue(r, "r");
        requireValue(s, "s");
        final List<ASN1Object> vector = new ArrayList<ASN1Object>();
        vector.add(new ASN1Integer(new BigInteger(1, r)));
        vector.add(new ASN1Integer(new BigInteger(1, s)));
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ASN1OutputStream asn1 = new ASN1OutputStream(new DEREncoder(), out)) {
            asn1.writeObject(new ASN1Sequence(vector));
        } catch (IOException e) {
            throw new SSHRuntimeException(e);
        }
        return new SecurityKeySignatureData(flags, counter, out.toByteArray());
    }

    /**
     * Creates the result for an {@code sk-ssh-ed25519@openssh.com} assertion from the signature an OpenSSH
     * security key middleware reports. It returns the whole 64-byte signature in {@code sig_r}, and
     * leaves {@code sig_s} unused.
     *
     * @param flags     the authenticator data flags the device returned
     * @param counter   the signature counter the device returned (an unsigned 32-bit value)
     * @param signature the raw 64-byte Ed25519 signature ({@code sig_r})
     * @return the signature data
     * @throws IllegalArgumentException if {@code signature} is not 64 bytes long
     */
    public static SecurityKeySignatureData ed25519(byte flags, long counter, byte[] signature) {
        if (signature == null || signature.length != ED25519_SIGNATURE_LENGTH) {
            throw new IllegalArgumentException("An Ed25519 signature is " + ED25519_SIGNATURE_LENGTH + " bytes long but got "
                    + (signature == null ? "none" : signature.length + " bytes"));
        }
        return new SecurityKeySignatureData(flags, counter, signature.clone());
    }

    private static void requireValue(byte[] value, String name) {
        if (value == null || value.length == 0) {
            throw new IllegalArgumentException("The ECDSA signature value " + name + " is missing");
        }
    }

    public byte getFlags() {
        return flags;
    }

    public long getCounter() {
        return counter;
    }

    public byte[] getSignature() {
        return signature.clone();
    }
}
