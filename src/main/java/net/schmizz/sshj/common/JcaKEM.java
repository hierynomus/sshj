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

import javax.crypto.SecretKey;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Implementation of {@link SshjKEM} backed by the JDK 21+ {@code javax.crypto.KEM} API,
 * accessed reflectively so that this class compiles on Java 8 source level.
 *
 * <p>On Java versions older than 21 the {@code javax.crypto.KEM} class is absent and the
 * static initializer leaves {@link #API_AVAILABLE} {@code false}. Callers should query
 * {@link #isApiAvailable()} (or call through {@link SecurityUtils#getKEM(String)}, which
 * throws {@link NoSuchAlgorithmException} when the API is missing) before using this class.</p>
 */
final class JcaKEM implements SshjKEM {

    private static final boolean API_AVAILABLE;
    private static final Method GET_INSTANCE;
    private static final Method GET_INSTANCE_PROVIDER;
    private static final Method NEW_ENCAPSULATOR;
    private static final Method NEW_DECAPSULATOR;
    private static final Method ENCAPSULATE;
    private static final Method ENCAPSULATION;
    private static final Method KEY;
    private static final Method DECAPSULATE;

    static {
        Method gi = null;
        Method gip = null;
        Method ne = null;
        Method nd = null;
        Method e = null;
        Method en = null;
        Method k = null;
        Method d = null;
        boolean available = false;
        try {
            Class<?> kemClass = Class.forName("javax.crypto.KEM");
            gi = kemClass.getMethod("getInstance", String.class);
            gip = kemClass.getMethod("getInstance", String.class, String.class);
            ne = kemClass.getMethod("newEncapsulator", PublicKey.class);
            nd = kemClass.getMethod("newDecapsulator", PrivateKey.class);
            Class<?> encapsulatorClass = Class.forName("javax.crypto.KEM$Encapsulator");
            e = encapsulatorClass.getMethod("encapsulate");
            Class<?> encapsulatedClass = Class.forName("javax.crypto.KEM$Encapsulated");
            en = encapsulatedClass.getMethod("encapsulation");
            k = encapsulatedClass.getMethod("key");
            Class<?> decapsulatorClass = Class.forName("javax.crypto.KEM$Decapsulator");
            d = decapsulatorClass.getMethod("decapsulate", byte[].class);
            available = true;
        } catch (Throwable t) {
            // Java < 21: javax.crypto.KEM not present. API_AVAILABLE stays false.
        }
        API_AVAILABLE = available;
        GET_INSTANCE = gi;
        GET_INSTANCE_PROVIDER = gip;
        NEW_ENCAPSULATOR = ne;
        NEW_DECAPSULATOR = nd;
        ENCAPSULATE = e;
        ENCAPSULATION = en;
        KEY = k;
        DECAPSULATE = d;
    }

    static boolean isApiAvailable() {
        return API_AVAILABLE;
    }

    static JcaKEM create(String algorithm, String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        if (!API_AVAILABLE) {
            throw new NoSuchAlgorithmException("javax.crypto.KEM is not available; Java 21 or later is required");
        }
        try {
            Object kem = (provider == null)
                    ? GET_INSTANCE.invoke(null, algorithm)
                    : GET_INSTANCE_PROVIDER.invoke(null, algorithm, provider);
            return new JcaKEM(kem);
        } catch (InvocationTargetException ite) {
            Throwable cause = ite.getCause();
            if (cause instanceof NoSuchAlgorithmException) {
                throw (NoSuchAlgorithmException) cause;
            }
            if (cause instanceof NoSuchProviderException) {
                throw (NoSuchProviderException) cause;
            }
            NoSuchAlgorithmException nae = new NoSuchAlgorithmException(
                    "Failed to obtain KEM instance for algorithm " + algorithm);
            nae.initCause(cause);
            throw nae;
        } catch (IllegalAccessException iae) {
            NoSuchAlgorithmException nae = new NoSuchAlgorithmException("Failed to access javax.crypto.KEM");
            nae.initCause(iae);
            throw nae;
        }
    }

    private final Object kem;

    private JcaKEM(Object kem) {
        this.kem = kem;
    }

    @Override
    public Encapsulated encapsulate(PublicKey peerPublicKey) throws GeneralSecurityException {
        try {
            Object encapsulator = NEW_ENCAPSULATOR.invoke(kem, peerPublicKey);
            Object result = ENCAPSULATE.invoke(encapsulator);
            byte[] ciphertext = (byte[]) ENCAPSULATION.invoke(result);
            SecretKey sharedSecret = (SecretKey) KEY.invoke(result);
            return new Encapsulated(ciphertext, sharedSecret.getEncoded());
        } catch (InvocationTargetException ite) {
            throw rethrow(ite);
        } catch (IllegalAccessException iae) {
            throw new GeneralSecurityException(iae);
        }
    }

    @Override
    public byte[] decapsulate(PrivateKey ourPrivateKey, byte[] ciphertext) throws GeneralSecurityException {
        try {
            Object decapsulator = NEW_DECAPSULATOR.invoke(kem, ourPrivateKey);
            SecretKey sharedSecret = (SecretKey) DECAPSULATE.invoke(decapsulator, (Object) ciphertext);
            return sharedSecret.getEncoded();
        } catch (InvocationTargetException ite) {
            throw rethrow(ite);
        } catch (IllegalAccessException iae) {
            throw new GeneralSecurityException(iae);
        }
    }

    private static GeneralSecurityException rethrow(InvocationTargetException ite) {
        Throwable cause = ite.getCause();
        if (cause instanceof GeneralSecurityException) {
            return (GeneralSecurityException) cause;
        }
        if (cause instanceof RuntimeException) {
            throw (RuntimeException) cause;
        }
        return new GeneralSecurityException(cause);
    }
}
