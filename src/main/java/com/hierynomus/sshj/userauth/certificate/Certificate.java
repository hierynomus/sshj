package com.hierynomus.sshj.userauth.certificate;

import java.security.PublicKey;
import java.util.Date;
import java.util.List;
import java.util.Map;

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
/**
 * Certificate wrapper for public keys, created to help implement
 * protocol described here:
 *
 * https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
 *
 * Consumed primarily by net.shmizz.sshj.common.KeyType
 *
 * @param <T> inner public key type
 */
public class Certificate<T extends PublicKey> implements PublicKey {
    private static final long serialVersionUID = 1L;

    private T publicKey;
    private byte[] nonce;
    private long serial;
    private long type;
    private String id;
    private List<String> validPrincipals;
    private Date validAfter;
    private Date validBefore;
    private Map<String, String> critOptions;
    private Map<String, String> extensions;
    private byte[] signatureKey;
    private byte[] signature;

    public Certificate(T delegate,
                          byte[] nonce,
                          long serial,
                          long type,
                          String id,
                          List<String> validPrincipals,
                          Date validAfter,
                          Date validBefore,
                          Map<String, String> critOptions,
                          Map<String, String> extensions,
                          byte[] signatureKey,
                          byte[] signature) {
        this.publicKey = delegate;
        this.nonce = nonce;
        this.serial = serial;
        this.type = type;
        this.id = id;
        this.validPrincipals = validPrincipals;
        this.validAfter = validAfter;
        this.validBefore = validBefore;
        this.critOptions = critOptions;
        this.extensions = extensions;
        this.signatureKey = signatureKey;
        this.signature = signature;
    }

    public byte[] getNonce() {
        return nonce;
    }

    public long getSerial() {
        return serial;
    }

    public long getType() {
        return type;
    }

    public String getId() {
        return id;
    }

    public List<String> getValidPrincipals() {
        return validPrincipals;
    }

    public Date getValidAfter() {
        return validAfter;
    }

    public Date getValidBefore() {
        return validBefore;
    }

    public Map<String, String> getCritOptions() {
        return critOptions;
    }

    public Map<String, String> getExtensions() {
        return extensions;
    }

    public byte[] getSignatureKey() {
        return signatureKey;
    }

    public byte[] getSignature() {
        return signature;
    }

    public T getKey() {
        return publicKey;
    }

    @Override
    public byte[] getEncoded() {
        return publicKey.getEncoded();
    }

    @Override
    public String getAlgorithm() {
        return publicKey.getAlgorithm();
    }

    @Override
    public String getFormat() {
        return publicKey.getFormat();
    }
}
