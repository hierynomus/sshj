/*
 * Copyright 2010 Shikhar Bhushan
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

import java.security.Key;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public enum KeyType {

    /** SSH identifier for RSA keys */
    RSA("ssh-rsa", new KeyChecker() {
        public boolean isMyType(Key key) {
            return (key instanceof RSAPublicKey || key instanceof RSAPrivateKey);
        }
    }),

    /** SSH identifier for DSA keys */
    DSA("ssh-dss", new KeyChecker() {
        public boolean isMyType(Key key) {
            return (key instanceof DSAPublicKey || key instanceof DSAPrivateKey);
        }
    }),

    /** Unrecognized */
    UNKNOWN("unknown", null);

    private static interface KeyChecker {
        boolean isMyType(Key key);
    }

    private final String sType;
    private final KeyChecker checker;

    private KeyType(String type, KeyChecker checker) {
        this.sType = type;
        this.checker = checker;
    }

    public static KeyType fromKey(Key key) {
        for (KeyType kt : values())
            if (kt.checker != null && kt.checker.isMyType((key)))
                return kt;
        return UNKNOWN;
    }

    public static KeyType fromString(String sType) {
        for (KeyType kt : values())
            if (kt.sType.equals(sType))
                return kt;
        return UNKNOWN;
    }

    @Override
    public String toString() {
        return sType;
    }

}