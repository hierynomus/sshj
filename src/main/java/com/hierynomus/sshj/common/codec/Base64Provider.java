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

import java.lang.reflect.Method;

/**
 * Base64 Provider enables compatibility with platforms that do not include java.util.Base64 such as Java 7
 */
public class Base64Provider {
    private static final boolean STANDARD_BASE64_SUPPORTED = isStandardBase64Supported();

    public static Base64Decoder getDecoder() {
        return STANDARD_BASE64_SUPPORTED ? new StandardBase64Decoder() : new BouncyCastleBase64Decoder();
    }

    public static Base64Encoder getEncoder() {
        return STANDARD_BASE64_SUPPORTED ? new StandardBase64Encoder() : new BouncyCastleBase64Encoder();
    }

    static Object getStandardDecoder() {
        final Class<?> standardClass = getStandardBase64Class();
        if (standardClass == null) {
            return null;
        }
        try {
            final Method method = standardClass.getMethod("getDecoder");
            return method.invoke(null);
        } catch (final Throwable e) {
            return null;
        }
    }

    static Object getStandardEncoder() {
        final Class<?> standardClass = getStandardBase64Class();
        if (standardClass == null) {
            return null;
        }
        try {
            final Method method = standardClass.getMethod("getEncoder");
            return method.invoke(null);
        } catch (final Throwable e) {
            return null;
        }
    }

    static boolean isStandardBase64Supported() {
        return getStandardBase64Class() != null;
    }

    static Class<?> getStandardBase64Class() {
        try {
            return Class.forName("java.util.Base64");
        } catch (final Throwable e) {
            return null;
        }
    }
}
