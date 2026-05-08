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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * Implementation of {@link SshjKEM} backed by Bouncy Castle's lightweight ML-KEM API
 * ({@code org.bouncycastle.pqc.crypto.mlkem}), accessed entirely via reflection so
 * that this class compiles, loads and verifies even when Bouncy Castle is absent
 * from the runtime classpath (e.g. shaded out by a downstream consumer).
 *
 * <p>This is a fallback used by {@link SecurityUtils#getKEM(String)} when the JDK
 * 21+ {@code javax.crypto.KEM} API is not available (i.e. on Java 8&ndash;20).
 * Callers should query {@link #isAvailable()} first.</p>
 */
final class BouncyCastleKEM implements SshjKEM {

    /** BC ML-KEM family name (parameter set inferred from the encoded key). */
    private static final String ML_KEM = "ML-KEM";

    private static final boolean AVAILABLE;
    private static final Constructor<?> GENERATOR_CTOR;
    private static final Method GENERATE_ENCAPSULATED;
    private static final Method GET_ENCAPSULATION;
    private static final Method GET_SECRET;
    private static final Method DESTROY;
    private static final Constructor<?> EXTRACTOR_CTOR;
    private static final Class<?> MLKEM_PRIVATE_KEY_PARAMETERS;
    private static final Method EXTRACT_SECRET;
    private static final Method PUBLIC_KEY_FACTORY_CREATE;
    private static final Method PRIVATE_KEY_FACTORY_CREATE;

    static {
        boolean available = false;
        Constructor<?> generatorCtor = null;
        Method generateEncapsulated = null;
        Method getEncapsulation = null;
        Method getSecret = null;
        Method destroy = null;
        Constructor<?> extractorCtor = null;
        Class<?> mlkemPrivateKeyParameters = null;
        Method extractSecret = null;
        Method publicKeyFactoryCreate = null;
        Method privateKeyFactoryCreate = null;
        try {
            Class<?> generator = Class.forName("org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator");
            Class<?> extractor = Class.forName("org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor");
            mlkemPrivateKeyParameters = Class.forName("org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters");
            Class<?> asymmetricKeyParameter = Class.forName("org.bouncycastle.crypto.params.AsymmetricKeyParameter");
            Class<?> secretWithEncapsulation = Class.forName("org.bouncycastle.crypto.SecretWithEncapsulation");
            Class<?> publicKeyFactory = Class.forName("org.bouncycastle.pqc.crypto.util.PublicKeyFactory");
            Class<?> privateKeyFactory = Class.forName("org.bouncycastle.pqc.crypto.util.PrivateKeyFactory");

            generatorCtor = generator.getConstructor(SecureRandom.class);
            generateEncapsulated = generator.getMethod("generateEncapsulated", asymmetricKeyParameter);
            getEncapsulation = secretWithEncapsulation.getMethod("getEncapsulation");
            getSecret = secretWithEncapsulation.getMethod("getSecret");
            destroy = secretWithEncapsulation.getMethod("destroy");
            extractorCtor = extractor.getConstructor(mlkemPrivateKeyParameters);
            extractSecret = extractor.getMethod("extractSecret", byte[].class);
            publicKeyFactoryCreate = publicKeyFactory.getMethod("createKey", byte[].class);
            privateKeyFactoryCreate = privateKeyFactory.getMethod("createKey", byte[].class);

            available = true;
        } catch (Throwable t) {
            // Bouncy Castle PQC absent or incompatible: fallback unavailable.
        }
        AVAILABLE = available;
        GENERATOR_CTOR = generatorCtor;
        GENERATE_ENCAPSULATED = generateEncapsulated;
        GET_ENCAPSULATION = getEncapsulation;
        GET_SECRET = getSecret;
        DESTROY = destroy;
        EXTRACTOR_CTOR = extractorCtor;
        MLKEM_PRIVATE_KEY_PARAMETERS = mlkemPrivateKeyParameters;
        EXTRACT_SECRET = extractSecret;
        PUBLIC_KEY_FACTORY_CREATE = publicKeyFactoryCreate;
        PRIVATE_KEY_FACTORY_CREATE = privateKeyFactoryCreate;
    }

    static boolean isAvailable() {
        return AVAILABLE;
    }

    static BouncyCastleKEM create(String algorithm) throws NoSuchAlgorithmException {
        if (!AVAILABLE) {
            throw new NoSuchAlgorithmException(
                    "Bouncy Castle PQC is not available; cannot fall back from javax.crypto.KEM");
        }
        if (!ML_KEM.equals(algorithm)) {
            throw new NoSuchAlgorithmException(
                    "Bouncy Castle KEM fallback only supports " + ML_KEM + ", requested " + algorithm);
        }
        return new BouncyCastleKEM();
    }

    private BouncyCastleKEM() {
    }

    @Override
    public Encapsulated encapsulate(PublicKey peerPublicKey) throws GeneralSecurityException {
        try {
            Object params = PUBLIC_KEY_FACTORY_CREATE.invoke(null, (Object) peerPublicKey.getEncoded());
            Object generator = GENERATOR_CTOR.newInstance(new SecureRandom());
            Object result = GENERATE_ENCAPSULATED.invoke(generator, params);
            try {
                byte[] ciphertext = (byte[]) GET_ENCAPSULATION.invoke(result);
                byte[] sharedSecret = (byte[]) GET_SECRET.invoke(result);
                return new Encapsulated(ciphertext, sharedSecret);
            } finally {
                try {
                    DESTROY.invoke(result);
                } catch (Throwable ignore) {
                    // best-effort wipe
                }
            }
        } catch (InvocationTargetException ite) {
            throw rethrow(ite, "Failed to encapsulate via Bouncy Castle");
        } catch (ReflectiveOperationException roe) {
            throw new GeneralSecurityException("Failed to invoke Bouncy Castle ML-KEM API", roe);
        }
    }

    @Override
    public byte[] decapsulate(PrivateKey ourPrivateKey, byte[] ciphertext) throws GeneralSecurityException {
        try {
            Object params = PRIVATE_KEY_FACTORY_CREATE.invoke(null, (Object) ourPrivateKey.getEncoded());
            if (!MLKEM_PRIVATE_KEY_PARAMETERS.isInstance(params)) {
                throw new GeneralSecurityException(
                        "Expected ML-KEM private key but got " + params.getClass().getName());
            }
            Object extractor = EXTRACTOR_CTOR.newInstance(params);
            return (byte[]) EXTRACT_SECRET.invoke(extractor, (Object) ciphertext);
        } catch (InvocationTargetException ite) {
            throw rethrow(ite, "Failed to decapsulate via Bouncy Castle");
        } catch (ReflectiveOperationException roe) {
            throw new GeneralSecurityException("Failed to invoke Bouncy Castle ML-KEM API", roe);
        }
    }

    private static GeneralSecurityException rethrow(InvocationTargetException ite, String message) {
        Throwable cause = ite.getCause();
        if (cause instanceof GeneralSecurityException) {
            return (GeneralSecurityException) cause;
        }
        if (cause instanceof RuntimeException) {
            throw (RuntimeException) cause;
        }
        return new GeneralSecurityException(message, cause);
    }
}
