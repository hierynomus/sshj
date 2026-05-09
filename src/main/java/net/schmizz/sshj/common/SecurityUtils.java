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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;

import static java.lang.String.format;

import java.lang.reflect.InvocationTargetException;

/**
 * Static utility method relating to security facilities.
 */
public class SecurityUtils {
    private static final Logger LOG = LoggerFactory.getLogger(SecurityUtils.class);

    /**
     * Identifier for the BouncyCastle JCE provider
     */
    public static final String BOUNCY_CASTLE = "BC";

    /**
     * Identifier for the BouncyCastle JCE provider
     */
    public static final String SPONGY_CASTLE = "SC";

    /*
     * Security provider identifier. null = default JCE
     */
    private static String securityProvider = null;

    // relate to BC registration (or SpongyCastle on Android)
    private static Boolean registerBouncyCastle;
    private static boolean registrationDone;

    public static boolean registerSecurityProvider(String providerClassName) {
        Provider provider = null;
        try {
            Class<?> name = Class.forName(providerClassName);
            provider = (Provider) name.getDeclaredConstructor().newInstance();
        } catch (ClassNotFoundException e) {
            LOG.info("Security Provider class '{}' not found", providerClassName);
        } catch (InstantiationException e) {
            LOG.info("Security Provider class '{}' could not be created", providerClassName);
        } catch (IllegalAccessException e) {
            LOG.info("Security Provider class '{}' could not be accessed", providerClassName);
        } catch (InvocationTargetException e) {
            LOG.info("Security Provider class '{}' could not be created", providerClassName);
        } catch (NoSuchMethodException e) {
            LOG.info("Security Provider class '{}' does not have a no-args constructor", providerClassName);
        }

        if (provider == null) {
            return false;
        }

        try {
            if (Security.getProvider(provider.getName()) == null) {
                Security.addProvider(provider);
            }

            if (securityProvider == null) {
                MessageDigest.getInstance("MD5", provider);
                KeyAgreement.getInstance("DH", provider);
                setSecurityProvider(provider.getName());
                return true;
            }
        } catch (NoSuchAlgorithmException e) {
            LOG.info(format("Security Provider '%s' does not support necessary algorithm", providerClassName), e);
        } catch (Exception e) {
            LOG.info(format("Registration of Security Provider '%s' unexpectedly failed", providerClassName), e);
        }
        return false;
    }



    public static synchronized Cipher getCipher(String transformation)
            throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
        register();
        if (getSecurityProvider() == null)
            return Cipher.getInstance(transformation);
        else
            return Cipher.getInstance(transformation, getSecurityProvider());
    }

    /**
     * Computes the fingerprint for a public key, in the standard SSH format, e.g. "4b:69:6c:72:6f:79:20:77:61:73:20:68:65:72:65:21"
     *
     * @param key the public key
     * @return the fingerprint
     * @see <a href="http://tools.ietf.org/html/draft-friedl-secsh-fingerprint-00">specification</a>
     */
    public static String getFingerprint(PublicKey key) {
        MessageDigest md5;
        try {
            md5 = getMessageDigest("MD5");
        } catch (GeneralSecurityException e) {
            throw new SSHRuntimeException(e);
        }
        md5.update(new Buffer.PlainBuffer().putPublicKey(key).getCompactData());
        final String undelimited = ByteArrayUtils.toHex(md5.digest());
        assert undelimited.length() == 32 : "md5 contract";
        StringBuilder fp = new StringBuilder(undelimited.substring(0, 2));
        for (int i = 2; i <= undelimited.length() - 2; i += 2)
            fp.append(":").append(undelimited.substring(i, i + 2));
        return fp.toString();
    }

    /**
     * Creates a new instance of {@link KeyAgreement} with the given algorithm.
     *
     * @param algorithm key agreement algorithm
     * @return new instance
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static synchronized KeyAgreement getKeyAgreement(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        register();
        if (getSecurityProvider() == null)
            return KeyAgreement.getInstance(algorithm);
        else
            return KeyAgreement.getInstance(algorithm, getSecurityProvider());
    }

    /**
     * Creates a new instance of {@link KeyFactory} with the given algorithm.
     *
     * @param algorithm key factory algorithm e.g. RSA, DSA
     * @return new instance
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static synchronized KeyFactory getKeyFactory(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        register();
        if (getSecurityProvider() == null)
            return KeyFactory.getInstance(algorithm);
        else
            return KeyFactory.getInstance(algorithm, getSecurityProvider());
    }

    /**
     * Creates a new instance of {@link KeyPairGenerator} with the given algorithm.
     *
     * @param algorithm key pair generator algorithm
     * @return new instance
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static synchronized KeyPairGenerator getKeyPairGenerator(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        register();
        if (getSecurityProvider() == null)
            return KeyPairGenerator.getInstance(algorithm);
        else
            return KeyPairGenerator.getInstance(algorithm, getSecurityProvider());
    }

    /**
     * Creates a new instance of {@link SshjKEM} for the given algorithm.
     *
     * <p>Two backends are tried, in order:</p>
     * <ol>
     *   <li>The JDK 21+ {@code javax.crypto.KEM} API (accessed reflectively so this library
     *       still compiles at Java 8 source level), dispatched through the configured JCA
     *       provider chain.</li>
     *   <li>If the JCA path is unusable&mdash;either because the {@code javax.crypto.KEM}
     *       class is absent, or because no registered provider offers the requested KEM
     *       service&mdash;a Bouncy Castle lightweight-API fallback
     *       ({@code org.bouncycastle.pqc.crypto.mlkem}) is used when those classes are on
     *       the classpath. (BC&nbsp;1.80 ships the lightweight ML-KEM API on every JDK but
     *       only registers the JCA {@code KEM} service on JDK&nbsp;21+; the fallback covers
     *       older JDKs where BC's KeyPairGenerator/KeyFactory <em>are</em> registered yet
     *       its JCA KEM service is not.)</li>
     * </ol>
     *
     * @param algorithm KEM algorithm name (Bouncy Castle 1.80 registers ML-KEM under {@code "ML-KEM"};
     *                  the per-parameter-set name {@code "ML-KEM-768"} is selected via the keys passed
     *                  to {@link SshjKEM#encapsulate(java.security.PublicKey)} /
     *                  {@link SshjKEM#decapsulate(java.security.PrivateKey, byte[])})
     * @return new instance
     * @throws NoSuchAlgorithmException if neither backend can supply the algorithm
     * @throws NoSuchProviderException
     */
    public static synchronized SshjKEM getKEM(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        register();
        if (JcaKEM.isApiAvailable()) {
            try {
                return JcaKEM.create(algorithm, getSecurityProvider());
            } catch (NoSuchAlgorithmException jcaFailure) {
                if (!BouncyCastleKEM.isAvailable()) {
                    throw jcaFailure;
                }
                // Fall through to BC fallback: JCA KEM API present but no provider offers
                // the requested algorithm. Common on JDK 17/20 with BC 1.80, where BC
                // registers ML-KEM as KeyPairGenerator/KeyFactory but not as a KEM service.
            }
        }
        if (BouncyCastleKEM.isAvailable()) {
            return BouncyCastleKEM.create(algorithm);
        }
        throw new NoSuchAlgorithmException(
                "No KEM implementation available for " + algorithm
                        + " (requires Java 21+ for javax.crypto.KEM, or Bouncy Castle PQC on the classpath)");
    }

    /**
     * Tests whether a JCA service of the given type and algorithm is available with the
     * currently configured security provider chain (registering Bouncy Castle on demand,
     * if enabled, before probing).
     *
     * <p>Special-cased for {@code type == "KEM"}: the JCA {@code javax.crypto.KEM} class
     * was introduced in Java&nbsp;21, so on older runtimes a JCA provider's claim to
     * support a "KEM" service is moot. We therefore additionally check that either
     * the {@code javax.crypto.KEM} API class is present <em>and</em> a provider offers
     * the service, <em>or</em> the Bouncy Castle PQC fallback is available.</p>
     *
     * @param type      JCA service type (e.g. {@code "KeyPairGenerator"}, {@code "KeyFactory"},
     *                  {@code "KEM"}, {@code "Signature"}, ...)
     * @param algorithm JCA algorithm name as registered by the provider
     * @return {@code true} if a provider on the current chain offers the service
     */
    public static synchronized boolean isAlgorithmAvailable(String type, String algorithm) {
        register();
        if ("KEM".equals(type)) {
            if (JcaKEM.isApiAvailable() && hasProviderService(type, algorithm)) {
                return true;
            }
            return BouncyCastleKEM.isAvailable();
        }
        return hasProviderService(type, algorithm);
    }

    private static boolean hasProviderService(String type, String algorithm) {
        Provider[] providers;
        if (getSecurityProvider() == null) {
            providers = Security.getProviders();
        } else {
            Provider single = Security.getProvider(getSecurityProvider());
            providers = (single == null) ? new Provider[0] : new Provider[]{single};
        }
        for (Provider p : providers) {
            if (p.getService(type, algorithm) != null) {
                return true;
            }
        }
        return false;
    }

    /**
     * Create a new instance of {@link Mac} with the given algorithm.
     *
     * @param algorithm MAC algorithm
     * @return new instance
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static synchronized Mac getMAC(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        register();
        if (getSecurityProvider() == null)
            return Mac.getInstance(algorithm);
        else
            return Mac.getInstance(algorithm, getSecurityProvider());
    }

    /**
     * Create a new instance of {@link MessageDigest} with the given algorithm.
     *
     * @param algorithm MessageDigest algorithm name
     * @return new instance
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static synchronized MessageDigest getMessageDigest(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        register();
        if (getSecurityProvider() == null)
            return MessageDigest.getInstance(algorithm);
        else
            return MessageDigest.getInstance(algorithm, getSecurityProvider());
    }

    /**
     * Get the identifier for the registered security provider.
     *
     * @return JCE provider identifier
     */
    public static synchronized String getSecurityProvider() {
        register();
        return securityProvider;
    }

    public static synchronized Signature getSignature(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        register();
        if (getSecurityProvider() == null)
            return Signature.getInstance(algorithm);
        else
            return Signature.getInstance(algorithm, getSecurityProvider());
    }

    /**
     * Attempts registering BouncyCastle as security provider if it has not been previously attempted and returns
     * whether the registration succeeded.
     *
     * @return whether BC (or SC on Android) registered
     */
    public static synchronized boolean isBouncyCastleRegistered() {
        register();
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            String name = provider.getName();
            if (BOUNCY_CASTLE.equals(name) || SPONGY_CASTLE.equals(name)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Configure whether to register the Bouncy Castle Security Provider. Must be called prior to other methods
     *
     * @param registerBouncyCastle Enable or disable Bouncy Castle Provider registration on subsequent method invocation
     */
    public static synchronized void setRegisterBouncyCastle(boolean registerBouncyCastle) {
        SecurityUtils.registerBouncyCastle = registerBouncyCastle;
        registrationDone = false;
    }

    /**
     * Specifies the JCE security provider that should be used.
     *
     * @param securityProvider identifier for the security provider
     */
    public static synchronized void setSecurityProvider(String securityProvider) {
        SecurityUtils.securityProvider = securityProvider;
        if(null == securityProvider) {
            SecurityUtils.registerBouncyCastle = null;
        }
        registrationDone = false;
    }

    private static void register() {
        if (!registrationDone) {
            if (securityProvider == null && (registerBouncyCastle == null || registerBouncyCastle)) {
                registerSecurityProvider("org.bouncycastle.jce.provider.BouncyCastleProvider");
                if (securityProvider == null && registerBouncyCastle == null) {
                    LOG.info("BouncyCastle not registered, using the default JCE provider");
                } else if (securityProvider == null) {
                    LOG.error("Failed to register BouncyCastle as the default JCE provider");
                    throw new SSHRuntimeException("Failed to register BouncyCastle as the default JCE provider");
                }
            }
            registrationDone = true;
        }
    }
}
