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
package com.hierynomus.sshj.common;

public class KeyAlgorithm {

    public static final String RSA = "RSA";
    public static final String DSA = "DSA";

    /** Elliptic curve signature key algorithm for use with BouncyCastle **/
    public static final String ECDSA = "ECDSA";

    /** General elliptic curve algorithm identifier for use with BouncyCastle **/
    public static final String EC_BC = "EC";

    /** General elliptic curve algorithm identifier for use with the Android Keystore **/
    public static final String EC_KEYSTORE = "EC";
}
