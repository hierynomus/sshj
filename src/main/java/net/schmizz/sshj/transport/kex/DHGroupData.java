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
 *
 * This file may incorporate work covered by the following copyright and
 * permission notice:
 *
 *     Licensed to the Apache Software Foundation (ASF) under one
 *     or more contributor license agreements.  See the NOTICE file
 *     distributed with this work for additional information
 *     regarding copyright ownership.  The ASF licenses this file
 *     to you under the Apache License, Version 2.0 (the
 *     "License"); you may not use this file except in compliance
 *     with the License.  You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *      Unless required by applicable law or agreed to in writing,
 *      software distributed under the License is distributed on an
 *      "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *      KIND, either express or implied.  See the License for the
 *      specific language governing permissions and limitations
 *      under the License.
 */
package net.schmizz.sshj.transport.kex;

import java.math.BigInteger;

/** Simple class holding the data for DH group key exchanges. */
public final class DHGroupData {

    private static final BigInteger G = new BigInteger(new byte[]{2});

    private static final BigInteger P1 = new BigInteger(new byte[]{
            (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xC9, (byte) 0x0F, (byte) 0xDA, (byte) 0xA2, (byte) 0x21, (byte) 0x68, (byte) 0xC2,
            (byte) 0x34, (byte) 0xC4, (byte) 0xC6, (byte) 0x62, (byte) 0x8B, (byte) 0x80, (byte) 0xDC, (byte) 0x1C,
            (byte) 0xD1, (byte) 0x29, (byte) 0x02, (byte) 0x4E, (byte) 0x08, (byte) 0x8A, (byte) 0x67, (byte) 0xCC,
            (byte) 0x74, (byte) 0x02, (byte) 0x0B, (byte) 0xBE, (byte) 0xA6, (byte) 0x3B, (byte) 0x13, (byte) 0x9B,
            (byte) 0x22, (byte) 0x51, (byte) 0x4A, (byte) 0x08, (byte) 0x79, (byte) 0x8E, (byte) 0x34, (byte) 0x04,
            (byte) 0xDD, (byte) 0xEF, (byte) 0x95, (byte) 0x19, (byte) 0xB3, (byte) 0xCD, (byte) 0x3A, (byte) 0x43,
            (byte) 0x1B, (byte) 0x30, (byte) 0x2B, (byte) 0x0A, (byte) 0x6D, (byte) 0xF2, (byte) 0x5F, (byte) 0x14,
            (byte) 0x37, (byte) 0x4F, (byte) 0xE1, (byte) 0x35, (byte) 0x6D, (byte) 0x6D, (byte) 0x51, (byte) 0xC2,
            (byte) 0x45, (byte) 0xE4, (byte) 0x85, (byte) 0xB5, (byte) 0x76, (byte) 0x62, (byte) 0x5E, (byte) 0x7E,
            (byte) 0xC6, (byte) 0xF4, (byte) 0x4C, (byte) 0x42, (byte) 0xE9, (byte) 0xA6, (byte) 0x37, (byte) 0xED,
            (byte) 0x6B, (byte) 0x0B, (byte) 0xFF, (byte) 0x5C, (byte) 0xB6, (byte) 0xF4, (byte) 0x06, (byte) 0xB7,
            (byte) 0xED, (byte) 0xEE, (byte) 0x38, (byte) 0x6B, (byte) 0xFB, (byte) 0x5A, (byte) 0x89, (byte) 0x9F,
            (byte) 0xA5, (byte) 0xAE, (byte) 0x9F, (byte) 0x24, (byte) 0x11, (byte) 0x7C, (byte) 0x4B, (byte) 0x1F,
            (byte) 0xE6, (byte) 0x49, (byte) 0x28, (byte) 0x66, (byte) 0x51, (byte) 0xEC, (byte) 0xE6, (byte) 0x53,
            (byte) 0x81, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF
    });

    private static final BigInteger P14 = new BigInteger(new byte[]{
            (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xC9, (byte) 0x0F, (byte) 0xDA, (byte) 0xA2, (byte) 0x21, (byte) 0x68, (byte) 0xC2,
            (byte) 0x34, (byte) 0xC4, (byte) 0xC6, (byte) 0x62, (byte) 0x8B, (byte) 0x80, (byte) 0xDC, (byte) 0x1C,
            (byte) 0xD1, (byte) 0x29, (byte) 0x02, (byte) 0x4E, (byte) 0x08, (byte) 0x8A, (byte) 0x67, (byte) 0xCC,
            (byte) 0x74, (byte) 0x02, (byte) 0x0B, (byte) 0xBE, (byte) 0xA6, (byte) 0x3B, (byte) 0x13, (byte) 0x9B,
            (byte) 0x22, (byte) 0x51, (byte) 0x4A, (byte) 0x08, (byte) 0x79, (byte) 0x8E, (byte) 0x34, (byte) 0x04,
            (byte) 0xDD, (byte) 0xEF, (byte) 0x95, (byte) 0x19, (byte) 0xB3, (byte) 0xCD, (byte) 0x3A, (byte) 0x43,
            (byte) 0x1B, (byte) 0x30, (byte) 0x2B, (byte) 0x0A, (byte) 0x6D, (byte) 0xF2, (byte) 0x5F, (byte) 0x14,
            (byte) 0x37, (byte) 0x4F, (byte) 0xE1, (byte) 0x35, (byte) 0x6D, (byte) 0x6D, (byte) 0x51, (byte) 0xC2,
            (byte) 0x45, (byte) 0xE4, (byte) 0x85, (byte) 0xB5, (byte) 0x76, (byte) 0x62, (byte) 0x5E, (byte) 0x7E,
            (byte) 0xC6, (byte) 0xF4, (byte) 0x4C, (byte) 0x42, (byte) 0xE9, (byte) 0xA6, (byte) 0x37, (byte) 0xED,
            (byte) 0x6B, (byte) 0x0B, (byte) 0xFF, (byte) 0x5C, (byte) 0xB6, (byte) 0xF4, (byte) 0x06, (byte) 0xB7,
            (byte) 0xED, (byte) 0xEE, (byte) 0x38, (byte) 0x6B, (byte) 0xFB, (byte) 0x5A, (byte) 0x89, (byte) 0x9F,
            (byte) 0xA5, (byte) 0xAE, (byte) 0x9F, (byte) 0x24, (byte) 0x11, (byte) 0x7C, (byte) 0x4B, (byte) 0x1F,
            (byte) 0xE6, (byte) 0x49, (byte) 0x28, (byte) 0x66, (byte) 0x51, (byte) 0xEC, (byte) 0xE4, (byte) 0x5B,
            (byte) 0x3D, (byte) 0xC2, (byte) 0x00, (byte) 0x7C, (byte) 0xB8, (byte) 0xA1, (byte) 0x63, (byte) 0xBF,
            (byte) 0x05, (byte) 0x98, (byte) 0xDA, (byte) 0x48, (byte) 0x36, (byte) 0x1C, (byte) 0x55, (byte) 0xD3,
            (byte) 0x9A, (byte) 0x69, (byte) 0x16, (byte) 0x3F, (byte) 0xA8, (byte) 0xFD, (byte) 0x24, (byte) 0xCF,
            (byte) 0x5F, (byte) 0x83, (byte) 0x65, (byte) 0x5D, (byte) 0x23, (byte) 0xDC, (byte) 0xA3, (byte) 0xAD,
            (byte) 0x96, (byte) 0x1C, (byte) 0x62, (byte) 0xF3, (byte) 0x56, (byte) 0x20, (byte) 0x85, (byte) 0x52,
            (byte) 0xBB, (byte) 0x9E, (byte) 0xD5, (byte) 0x29, (byte) 0x07, (byte) 0x70, (byte) 0x96, (byte) 0x96,
            (byte) 0x6D, (byte) 0x67, (byte) 0x0C, (byte) 0x35, (byte) 0x4E, (byte) 0x4A, (byte) 0xBC, (byte) 0x98,
            (byte) 0x04, (byte) 0xF1, (byte) 0x74, (byte) 0x6C, (byte) 0x08, (byte) 0xCA, (byte) 0x18, (byte) 0x21,
            (byte) 0x7C, (byte) 0x32, (byte) 0x90, (byte) 0x5E, (byte) 0x46, (byte) 0x2E, (byte) 0x36, (byte) 0xCE,
            (byte) 0x3B, (byte) 0xE3, (byte) 0x9E, (byte) 0x77, (byte) 0x2C, (byte) 0x18, (byte) 0x0E, (byte) 0x86,
            (byte) 0x03, (byte) 0x9B, (byte) 0x27, (byte) 0x83, (byte) 0xA2, (byte) 0xEC, (byte) 0x07, (byte) 0xA2,
            (byte) 0x8F, (byte) 0xB5, (byte) 0xC5, (byte) 0x5D, (byte) 0xF0, (byte) 0x6F, (byte) 0x4C, (byte) 0x52,
            (byte) 0xC9, (byte) 0xDE, (byte) 0x2B, (byte) 0xCB, (byte) 0xF6, (byte) 0x95, (byte) 0x58, (byte) 0x17,
            (byte) 0x18, (byte) 0x39, (byte) 0x95, (byte) 0x49, (byte) 0x7C, (byte) 0xEA, (byte) 0x95, (byte) 0x6A,
            (byte) 0xE5, (byte) 0x15, (byte) 0xD2, (byte) 0x26, (byte) 0x18, (byte) 0x98, (byte) 0xFA, (byte) 0x05,
            (byte) 0x10, (byte) 0x15, (byte) 0x72, (byte) 0x8E, (byte) 0x5A, (byte) 0x8A, (byte) 0xAC, (byte) 0xAA,
            (byte) 0x68, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF
    });

    public static BigInteger getG() {
        return G;
    }

    public static BigInteger getP1() {
        return P1;
    }

    public static BigInteger getP14() {
        return P14;
    }

}
