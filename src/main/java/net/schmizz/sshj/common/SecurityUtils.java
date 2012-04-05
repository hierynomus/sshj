/*
 * Copyright 2010-2012 sshj contributors
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
package net.schmizz.sshj.common;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;

// TODO refactor

/** Static utility method relating to security facilities. */
public class SecurityUtils {

    private static class BouncyCastleRegistration {

        public void run()
                throws Exception {
            if (java.security.Security.getProvider(BOUNCY_CASTLE) == null) {
                LOG.info("Trying to register BouncyCastle as a JCE provider");
                java.security.Security.addProvider(new BouncyCastleProvider());
                MessageDigest.getInstance("MD5", BOUNCY_CASTLE);
                KeyAgreement.getInstance("DH", BOUNCY_CASTLE);
                LOG.info("Registration succeeded");
            } else
                LOG.info("BouncyCastle already registered as a JCE provider");
            securityProvider = BOUNCY_CASTLE;
        }
    }

    private static final Logger LOG = LoggerFactory.getLogger(SecurityUtils.class);

    /** Identifier for the BouncyCastle JCE provider */
    public static final String BOUNCY_CASTLE = "BC";

    /*
    * Security provider identifier. null = default JCE
    */
    private static String securityProvider = null;

    // relate to BC registration
    private static Boolean registerBouncyCastle;
    private static boolean registrationDone;

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
     *
     * @return the fingerprint
     *
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
     *
     * @return new instance
     *
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
     *
     * @return new instance
     *
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
     *
     * @return new instance
     *
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
     * Create a new instance of {@link Mac} with the given algorithm.
     *
     * @param algorithm MAC algorithm
     *
     * @return new instance
     *
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
     *
     * @return new instance
     *
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
     * @return whether BC registered
     */
    public static synchronized boolean isBouncyCastleRegistered() {
        register();
        return BOUNCY_CASTLE.equals(securityProvider);
    }

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
        registrationDone = false;
    }

    private static void register() {
        if (!registrationDone) {
            if (securityProvider == null && (registerBouncyCastle == null || registerBouncyCastle))
                // Use an inner class to avoid a strong dependency on BouncyCastle
                try {
                    new BouncyCastleRegistration().run();
                } catch (Throwable t) {
                    if (registerBouncyCastle == null)
                        LOG.info("BouncyCastle not registered, using the default JCE provider");
                    else {
                        LOG.error("Failed to register BouncyCastle as the defaut JCE provider");
                        throw new SSHRuntimeException("Failed to register BouncyCastle as the defaut JCE provider", t);
                    }
                }
            registrationDone = true;
        }
    }

}