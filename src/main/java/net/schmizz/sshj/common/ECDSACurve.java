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
package net.schmizz.sshj.common;

/**
 * Enumeration of supported ECDSA Curves with corresponding algorithm parameter names
 */
public enum ECDSACurve {
    /** NIST P-256 */
    SECP256R1("secp256r1"),

    /** NIST P-384 */
    SECP384R1("secp384r1"),

    /** NIST P-521 */
    SECP521R1("secp521r1");

    private final String curveName;

    ECDSACurve(final String curveName) {
        this.curveName = curveName;
    }

    /**
     * Get Curve Name for use with Java Cryptography Architecture components
     *
     * @return Curve Name
     */
    public String getCurveName() {
        return curveName;
    }
}
