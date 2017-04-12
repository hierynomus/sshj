package com.hierynomus.sshj.userauth.certificate;

import java.math.BigInteger;
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

    private final T publicKey;
    private final byte[] nonce;
    private final BigInteger serial;
    private final long type;
    private final String id;
    private final List<String> validPrincipals;
    private final Date validAfter;
    private final Date validBefore;
    private final Map<String, String> critOptions;
    private final Map<String, String> extensions;
    private final byte[] signatureKey;
    private final byte[] signature;

    Certificate(Builder<T> builder) {
        this.publicKey = builder.getPublicKey();
        this.nonce = builder.getNonce();
        this.serial = builder.getSerial();
        this.type = builder.getType();
        this.id = builder.getId();
        this.validPrincipals = builder.getValidPrincipals();
        this.validAfter = builder.getValidAfter();
        this.validBefore = builder.getValidBefore();
        this.critOptions = builder.getCritOptions();
        this.extensions = builder.getExtensions();
        this.signatureKey = builder.getSignatureKey();
        this.signature = builder.getSignature();
    }

    public static <P extends PublicKey> Builder<P> getBuilder() {
        return new Builder<P>();
    }

    public byte[] getNonce() {
        return nonce;
    }

    public BigInteger getSerial() {
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

    public static class Builder<T extends PublicKey> {
        private T publicKey;
        private byte[] nonce;
        private BigInteger serial;
        private long type;
        private String id;
        private List<String> validPrincipals;
        private Date validAfter;
        private Date validBefore;
        private Map<String, String> critOptions;
        private Map<String, String> extensions;
        private byte[] signatureKey;
        private byte[] signature;

        public Certificate<T> build() {
            return new Certificate<T>(this);
        }

        public T getPublicKey() {
            return publicKey;
        }

        public Builder<T> publicKey(T publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        public byte[] getNonce() {
            return nonce;
        }

        public Builder<T> nonce(byte[] nonce) {
            this.nonce = nonce;
            return this;
        }

        public BigInteger getSerial() {
            return serial;
        }

        public Builder<T> serial(BigInteger serial) {
            this.serial = serial;
            return this;
        }

        public long getType() {
            return type;
        }

        public Builder<T> type(long type) {
            this.type = type;
            return this;
        }

        public String getId() {
            return id;
        }

        public Builder<T> id(String id) {
            this.id = id;
            return this;
        }

        public List<String> getValidPrincipals() {
            return validPrincipals;
        }

        public Builder<T> validPrincipals(List<String> validPrincipals) {
            this.validPrincipals = validPrincipals;
            return this;
        }

        public Date getValidAfter() {
            return validAfter;
        }

        public Builder<T> validAfter(Date validAfter) {
            this.validAfter = validAfter;
            return this;
        }

        public Date getValidBefore() {
            return validBefore;
        }

        public Builder<T> validBefore(Date validBefore) {
            this.validBefore = validBefore;
            return this;
        }

        public Map<String, String> getCritOptions() {
            return critOptions;
        }

        public Builder<T> critOptions(Map<String, String> critOptions) {
            this.critOptions = critOptions;
            return this;
        }

        public Map<String, String> getExtensions() {
            return extensions;
        }

        public Builder<T> extensions(Map<String, String> extensions) {
            this.extensions = extensions;
            return this;
        }

        public byte[] getSignatureKey() {
            return signatureKey;
        }

        public Builder<T> signatureKey(byte[] signatureKey) {
            this.signatureKey = signatureKey;
            return this;
        }

        public byte[] getSignature() {
            return signature;
        }

        public Builder<T> signature(byte[] signature) {
            this.signature = signature;
            return this;
        }
    }
}
