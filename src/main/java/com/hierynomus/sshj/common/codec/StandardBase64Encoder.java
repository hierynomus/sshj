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
 * Standard implementation of Base64 Encoder using java.util.Base64.Encoder
 */
public class StandardBase64Encoder implements Base64Encoder {
    private static final Object ENCODER = Base64Provider.getStandardEncoder();

    private static final Method ENCODE_METHOD = getEncodeToStringMethod();

    @Override
    public String encode(final byte[] bytes) {
        try {
            return (String) ENCODE_METHOD.invoke(ENCODER, bytes);
        } catch (final IllegalAccessException| InvocationTargetException e) {
            throw new IllegalStateException("Base64.Encoder.encodeToString() invocation failed", e);
        }
    }

    private static Method getEncodeToStringMethod() {
        if (ENCODER == null) {
            throw new IllegalStateException("Base64.Encoder not found");
        }
        try {
            final Class<?> encoderClass = ENCODER.getClass();
            return encoderClass.getMethod("encodeToString", byte[].class);
        } catch (final NoSuchMethodException e) {
            throw new IllegalArgumentException("Base64.Encoder.encodeToString() not found", e);
        }
    }
}
