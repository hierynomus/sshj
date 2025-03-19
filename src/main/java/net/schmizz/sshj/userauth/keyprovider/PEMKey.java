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
package net.schmizz.sshj.userauth.keyprovider;

import java.util.List;
import java.util.Objects;

/**
 * PEM Key container with identified Key Type and decoded body
 */
public class PEMKey {
    private final PEMKeyType pemKeyType;

    private final List<String> headers;

    private final byte[] body;

    PEMKey(final PEMKeyType pemKeyType, final List<String> headers, final byte[] body) {
        this.pemKeyType = Objects.requireNonNull(pemKeyType, "PEM Key Type required");
        this.headers = Objects.requireNonNull(headers, "Headers required");
        this.body = Objects.requireNonNull(body, "Body required");
    }

    PEMKeyType getPemKeyType() {
        return pemKeyType;
    }

    List<String> getHeaders() {
        return headers;
    }

    byte[] getBody() {
        return body.clone();
    }

    public enum PEMKeyType {
        /** RFC 3279 Section 2.3.2 */
        DSA("-----BEGIN DSA PRIVATE KEY-----"),

        /** RFC 5915 Section 3 */
        EC("-----BEGIN EC PRIVATE KEY-----"),

        /** RFC 8017 Appendix 1.2 */
        RSA("-----BEGIN RSA PRIVATE KEY-----"),

        /** RFC 5208 Section 5 */
        PKCS8("-----BEGIN PRIVATE KEY-----"),

        /** RFC 5208 Section 6 */
        PKCS8_ENCRYPTED("-----BEGIN ENCRYPTED PRIVATE KEY-----");

        private final String header;

        PEMKeyType(final String header) {
            this.header = header;
        }

        String getHeader() {
            return header;
        }
    }
}
