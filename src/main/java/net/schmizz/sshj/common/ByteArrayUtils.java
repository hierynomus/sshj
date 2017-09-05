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

/** Utility functions for byte arrays. */
public class ByteArrayUtils {

    final static char[] digits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    /**
     * Check whether some part or whole of two byte arrays is equal, for <code>length</code> bytes starting at some
     * offset.
     *
     * @param a1
     * @param a1Offset
     * @param a2
     * @param a2Offset
     * @param length
     *
     * @return <code>true</code> or <code>false</code>
     */
    public static boolean equals(byte[] a1, int a1Offset, byte[] a2, int a2Offset, int length) {
        if (a1.length < a1Offset + length || a2.length < a2Offset + length)
            return false;
        while (length-- > 0)
            if (a1[a1Offset++] != a2[a2Offset++])
                return false;
        return true;
    }

    /**
     * Get a hexadecimal representation of a byte array starting at <code>offset</code> index for <code>len</code>
     * bytes, with each octet separated by a space.
     *
     * @param array
     * @param offset
     * @param len
     *
     * @return hex string, each octet delimited by a space
     */
    public static String printHex(byte[] array, int offset, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            byte b = array[offset + i];
            if (sb.length() > 0)
                sb.append(' ');
            sb.append(digits[b >> 4 & 0x0F]);
            sb.append(digits[b & 0x0F]);
        }
        return sb.toString();
    }

    /**
     * Get the hexadecimal representation of a byte array.
     *
     * @param array
     *
     * @return hex string
     */
    public static String toHex(byte[] array) {
        return toHex(array, 0, array.length);
    }

    /**
     * Get the hexadecimal representation of a byte array starting at <code>offset</code> index for <code>len</code>
     * bytes.
     *
     * @param array
     * @param offset
     * @param len
     *
     * @return hex string
     */
    public static String toHex(byte[] array, int offset, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            byte b = array[offset + i];
            sb.append(digits[b >> 4 & 0x0F]);
            sb.append(digits[b & 0x0F]);
        }
        return sb.toString();
    }


    public static byte[] parseHex(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("Hex string is null");
        }
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string '" + hex + "' should have even length.");
        }

        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int hi = parseHexDigit(hex.charAt(i * 2)) << 4;
            int lo = parseHexDigit(hex.charAt(i * 2 + 1));
            result[i] = (byte) (hi + lo);
        }
        return result;
    }

    private static int parseHexDigit(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        throw new IllegalArgumentException("Digit '" + c + "' out of bounds [0-9a-fA-F]");
    }
}
