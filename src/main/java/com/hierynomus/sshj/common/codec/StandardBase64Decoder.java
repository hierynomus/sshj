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
package com.hierynomus.sshj.common.codec;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Standard implementation of Base64 Decoder using java.util.Base64.Decoder
 */
public class StandardBase64Decoder implements Base64Decoder {
    private static final Object DECODER = Base64Provider.getStandardDecoder();

    private static final Method DECODE_METHOD = getDecodeMethod();

    @Override
    public byte[] decode(final String encoded) {
        try {
            return (byte[]) DECODE_METHOD.invoke(DECODER, encoded);
        } catch (final IllegalAccessException|InvocationTargetException e) {
            throw new IllegalStateException("Base64.Decoder.decode() invocation failed", e);
        }
    }

    private static Method getDecodeMethod() {
        if (DECODER == null) {
            throw new IllegalStateException("Base64.Decoder not found");
        }
        try {
            final Class<?> decoderClass = DECODER.getClass();
            return decoderClass.getMethod("decode", String.class);
        } catch (final NoSuchMethodException e) {
            throw new IllegalArgumentException("Base64.Decoder.decode() not found", e);
        }
    }
}
