// Copyright (c) 2006 Damien Miller <djm@mindrot.org>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package com.hierynomus.sshj.userauth.keyprovider.bcrypt;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * JUnit unit tests for BCrypt routines
 * @author Damien Miller
 * @version 0.2
 */
public class BCryptTest {
    String[][] test_vectors = {
            { "",
                    "$2a$06$DCq7YPn5Rq63x1Lad4cll.",
                    "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s." },
            { "",
                    "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.",
                    "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye" },
            { "",
                    "$2a$10$k1wbIrmNyFAPwPVPSVa/ze",
                    "$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW" },
            { "",
                    "$2a$12$k42ZFHFWqBp3vWli.nIn8u",
                    "$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO" },
            { "a",
                    "$2a$06$m0CrhHm10qJ3lXRY.5zDGO",
                    "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe" },
            { "a",
                    "$2a$08$cfcvVd2aQ8CMvoMpP2EBfe",
                    "$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V." },
            { "a",
                    "$2a$10$k87L/MF28Q673VKh8/cPi.",
                    "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u" },
            { "a",
                    "$2a$12$8NJH3LsPrANStV6XtBakCe",
                    "$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS" },
            { "abc",
                    "$2a$06$If6bvum7DFjUnE9p2uDeDu",
                    "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i" },
            { "abc",
                    "$2a$08$Ro0CUfOqk6cXEKf3dyaM7O",
                    "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm" },
            { "abc",
                    "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.",
                    "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi" },
            { "abc",
                    "$2a$12$EXRkfkdmXn2gzds2SSitu.",
                    "$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q" },
            { "abcdefghijklmnopqrstuvwxyz",
                    "$2a$06$.rCVZVOThsIa97pEDOxvGu",
                    "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC" },
            { "abcdefghijklmnopqrstuvwxyz",
                    "$2a$08$aTsUwsyowQuzRrDqFflhge",
                    "$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz." },
            { "abcdefghijklmnopqrstuvwxyz",
                    "$2a$10$fVH8e28OQRj9tqiDXs1e1u",
                    "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq" },
            { "abcdefghijklmnopqrstuvwxyz",
                    "$2a$12$D4G5f18o7aMMfwasBL7Gpu",
                    "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG" },
            { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
                    "$2a$06$fPIsBO8qRqkjj273rfaOI.",
                    "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO" },
            { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
                    "$2a$08$Eq2r4G/76Wv39MzSX262hu",
                    "$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW" },
            { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
                    "$2a$10$LgfYWkbzEvQ4JakH7rOvHe",
                    "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS" },
            { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
                    "$2a$12$WApznUOJfkEGSmYRfnkrPO",
                    "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC" },
    };

    /**
     * Test method for 'BCrypt.hashpw(String, String)'
     */
    @Test
    public void testHashpw() {
        System.out.print("BCrypt.hashpw(): ");
        for (int i = 0; i < test_vectors.length; i++) {
            String plain = test_vectors[i][0];
            String salt = test_vectors[i][1];
            String expected = test_vectors[i][2];
            String hashed = BCrypt.hashpw(plain, salt);
            assertEquals(hashed, expected);
            System.out.print(".");
        }
    }

    /**
     * Test method for 'BCrypt.gensalt(int)'
     */
    @Test
    public void testGensaltInt() {
        System.out.print("BCrypt.gensalt(log_rounds):");
        for (int i = 4; i <= 12; i++) {
            System.out.print(" " + i + ":");
            for (int j = 0; j < test_vectors.length; j += 4) {
                String plain = test_vectors[j][0];
                String salt = BCrypt.gensalt(i);
                String hashed1 = BCrypt.hashpw(plain, salt);
                String hashed2 = BCrypt.hashpw(plain, hashed1);
                assertEquals(hashed1, hashed2);
                System.out.print(".");
            }
        }
    }

    /**
     * Test method for 'BCrypt.gensalt()'
     */
    @Test
    public void testGensalt() {
        System.out.print("BCrypt.gensalt(): ");
        for (int i = 0; i < test_vectors.length; i += 4) {
            String plain = test_vectors[i][0];
            String salt = BCrypt.gensalt();
            String hashed1 = BCrypt.hashpw(plain, salt);
            String hashed2 = BCrypt.hashpw(plain, hashed1);
            assertEquals(hashed1, hashed2);
            System.out.print(".");
        }
    }

    /**
     * Test method for 'BCrypt.checkpw(String, String)'
     * expecting success
     */
    @Test
    public void testCheckpw_success() {
        System.out.print("BCrypt.checkpw w/ good passwords: ");
        for (int i = 0; i < test_vectors.length; i++) {
            String plain = test_vectors[i][0];
            String expected = test_vectors[i][2];
            assertTrue(BCrypt.checkpw(plain, expected));
            System.out.print(".");
        }
    }

    /**
     * Test method for 'BCrypt.checkpw(String, String)'
     * expecting failure
     */
    @Test
    public void testCheckpw_failure() {
        System.out.print("BCrypt.checkpw w/ bad passwords: ");
        for (int i = 0; i < test_vectors.length; i++) {
            int broken_index = (i + 4) % test_vectors.length;
            String plain = test_vectors[i][0];
            String expected = test_vectors[broken_index][2];
            assertFalse(BCrypt.checkpw(plain, expected));
            System.out.print(".");
        }
    }

    /**
     * Test for correct hashing of non-US-ASCII passwords
     */
    @Test
    public void testInternationalChars() {
        System.out.print("BCrypt.hashpw w/ international chars: ");
        String pw1 = "\u2605\u2605\u2605\u2605\u2605\u2605\u2605\u2605";
        String pw2 = "????????";

        String h1 = BCrypt.hashpw(pw1, BCrypt.gensalt());
        assertFalse(BCrypt.checkpw(pw2, h1));
        System.out.print(".");

        String h2 = BCrypt.hashpw(pw2, BCrypt.gensalt());
        assertFalse(BCrypt.checkpw(pw1, h2));
        System.out.print(".");
    }

    private static class BCryptHashTV {
        private final byte[] pass;
        private final byte[] salt;
        private final byte[] out;

        public BCryptHashTV(byte[] pass, byte[] salt, byte[] out) {
            this.pass = pass;
            this.salt = salt;
            this.out = out;
        }
    }

    BCryptHashTV[] bcrypt_hash_test_vectors = new BCryptHashTV[]{
            new BCryptHashTV(
                    new byte[]{
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    },
                    new byte[]{
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    },
                    new byte[]{
                            (byte) 0x46, (byte) 0x02, (byte) 0x86, (byte) 0xe9, (byte) 0x72, (byte) 0xfa, (byte) 0x83, (byte) 0x3f, (byte) 0x8b, (byte) 0x12, (byte) 0x83, (byte) 0xad, (byte) 0x8f, (byte) 0xa9, (byte) 0x19, (byte) 0xfa,
                            (byte) 0x29, (byte) 0xbd, (byte) 0xe2, (byte) 0x0e, (byte) 0x23, (byte) 0x32, (byte) 0x9e, (byte) 0x77, (byte) 0x4d, (byte) 0x84, (byte) 0x22, (byte) 0xba, (byte) 0xc0, (byte) 0xa7, (byte) 0x92, (byte) 0x6c,
                    }),
            new BCryptHashTV(
                    new byte[] {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, },
                    new byte[] {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, },
                    new byte[] {
                            (byte) 0xc6, (byte) 0xa9, (byte) 0x5f, (byte) 0xe6, (byte) 0x41, (byte) 0x31, (byte) 0x15, (byte) 0xfb, (byte) 0x57, (byte) 0xe9, (byte) 0x9f, (byte) 0x75, (byte) 0x74, (byte) 0x98, (byte) 0xe8, (byte) 0x5d,
                            (byte) 0xa3, (byte) 0xc6, (byte) 0xe1, (byte) 0xdf, (byte) 0x0c, (byte) 0x3c, (byte) 0x93, (byte) 0xaa, (byte) 0x97, (byte) 0x5c, (byte) 0x54, (byte) 0x8a, (byte) 0x34, (byte) 0x43, (byte) 0x26, (byte) 0xf8,
                    }),
    };

    @Test
    public void testBCryptHashTestVectors() {
        System.out.print("BCrypt.hash w/ known vectors: ");
        for (BCryptHashTV tv : bcrypt_hash_test_vectors) {
            byte[] output = new byte[tv.out.length];
            new BCrypt().hash(tv.pass, tv.salt, output);
            assertEquals(Arrays.toString(tv.out), Arrays.toString(output));
            System.out.print(".");
        }
    }

    private static class BCryptPbkdfTV {
        private final byte[] pass;
        private final byte[] salt;
        private final int rounds;
        private final byte[] out;

        public BCryptPbkdfTV(byte[] pass, byte[] salt, int rounds, byte[] out) {
            this.pass = pass;
            this.salt = salt;
            this.rounds = rounds;
            this.out = out;
        }
    }

    BCryptPbkdfTV[] bcrypt_pbkdf_test_vectors = new BCryptPbkdfTV[]{
            new BCryptPbkdfTV("password".getBytes(), "salt".getBytes(), 4, new byte[]{
                    (byte) 0x5b, (byte) 0xbf, (byte) 0x0c, (byte) 0xc2, (byte) 0x93, (byte) 0x58, (byte) 0x7f, (byte) 0x1c, (byte) 0x36, (byte) 0x35, (byte) 0x55, (byte) 0x5c, (byte) 0x27, (byte) 0x79, (byte) 0x65, (byte) 0x98,
                    (byte) 0xd4, (byte) 0x7e, (byte) 0x57, (byte) 0x90, (byte) 0x71, (byte) 0xbf, (byte) 0x42, (byte) 0x7e, (byte) 0x9d, (byte) 0x8f, (byte) 0xbe, (byte) 0x84, (byte) 0x2a, (byte) 0xba, (byte) 0x34, (byte) 0xd9,
            }),
            new BCryptPbkdfTV("password".getBytes(), "salt".getBytes(), 8, new byte[]{
                    (byte) 0xe1, (byte) 0x36, (byte) 0x7e, (byte) 0xc5, (byte) 0x15, (byte) 0x1a, (byte) 0x33, (byte) 0xfa, (byte) 0xac, (byte) 0x4c, (byte) 0xc1, (byte) 0xc1, (byte) 0x44, (byte) 0xcd, (byte) 0x23, (byte) 0xfa,
                    (byte) 0x15, (byte) 0xd5, (byte) 0x54, (byte) 0x84, (byte) 0x93, (byte) 0xec, (byte) 0xc9, (byte) 0x9b, (byte) 0x9b, (byte) 0x5d, (byte) 0x9c, (byte) 0x0d, (byte) 0x3b, (byte) 0x27, (byte) 0xbe, (byte) 0xc7,
                    (byte) 0x62, (byte) 0x27, (byte) 0xea, (byte) 0x66, (byte) 0x08, (byte) 0x8b, (byte) 0x84, (byte) 0x9b, (byte) 0x20, (byte) 0xab, (byte) 0x7a, (byte) 0xa4, (byte) 0x78, (byte) 0x01, (byte) 0x02, (byte) 0x46,
                    (byte) 0xe7, (byte) 0x4b, (byte) 0xba, (byte) 0x51, (byte) 0x72, (byte) 0x3f, (byte) 0xef, (byte) 0xa9, (byte) 0xf9, (byte) 0x47, (byte) 0x4d, (byte) 0x65, (byte) 0x08, (byte) 0x84, (byte) 0x5e, (byte) 0x8d}),
            new BCryptPbkdfTV("password".getBytes(), "salt".getBytes(), 42, new byte[]{
                    (byte) 0x83, (byte) 0x3c, (byte) 0xf0, (byte) 0xdc, (byte) 0xf5, (byte) 0x6d, (byte) 0xb6, (byte) 0x56, (byte) 0x08, (byte) 0xe8, (byte) 0xf0, (byte) 0xdc, (byte) 0x0c, (byte) 0xe8, (byte) 0x82, (byte) 0xbd}),
    };

    @Test
    public void testBCryptPbkdfTestVectors() {
        System.out.print("BCrypt.pbkdf w/ known vectors: ");
        for (BCryptPbkdfTV tv : bcrypt_pbkdf_test_vectors) {
            byte[] output = new byte[tv.out.length];
            new BCrypt().pbkdf(tv.pass, tv.salt, tv.rounds, output);
            assertEquals(Arrays.toString(tv.out), Arrays.toString(output));
            System.out.print(".");
        }
    }
}
