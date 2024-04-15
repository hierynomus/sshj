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

import java.io.IOException;
import java.util.Base64;

/**
 * <p>Wraps {@link java.util.Base64.Decoder} in order to wrap unchecked {@code IllegalArgumentException} thrown by
 * the default Java Base64 decoder here and there.</p>
 *
 * <p>Please use this class instead of {@link java.util.Base64.Decoder}.</p>
 */
public class Base64Decoder {
    private Base64Decoder() {
    }

    public static byte[] decode(byte[] source) throws Base64DecodingException {
        try {
            return Base64.getDecoder().decode(source);
        } catch (IllegalArgumentException err) {
            throw new Base64DecodingException(err);
        }
    }

    public static byte[] decode(String src) throws Base64DecodingException {
        try {
            return Base64.getDecoder().decode(src);
        } catch (IllegalArgumentException err) {
            throw new Base64DecodingException(err);
        }
    }
}
