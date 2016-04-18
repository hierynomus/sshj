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
package net.schmizz.sshj;

import com.hierynomus.sshj.signature.SignatureEdDSA;
import com.hierynomus.sshj.transport.cipher.BlockCiphers;
import com.hierynomus.sshj.transport.cipher.StreamCiphers;
import net.schmizz.keepalive.KeepAliveProvider;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.signature.SignatureDSA;
import net.schmizz.sshj.signature.SignatureECDSA;
import net.schmizz.sshj.signature.SignatureRSA;
import net.schmizz.sshj.transport.cipher.AES128CBC;
import net.schmizz.sshj.transport.cipher.AES128CTR;
import net.schmizz.sshj.transport.cipher.AES192CBC;
import net.schmizz.sshj.transport.cipher.AES192CTR;
import net.schmizz.sshj.transport.cipher.AES256CBC;
import net.schmizz.sshj.transport.cipher.AES256CTR;
import net.schmizz.sshj.transport.cipher.BlowfishCBC;
import net.schmizz.sshj.transport.cipher.Cipher;
import net.schmizz.sshj.transport.cipher.TripleDESCBC;
import net.schmizz.sshj.transport.compression.NoneCompression;
import net.schmizz.sshj.transport.kex.*;
import net.schmizz.sshj.transport.mac.HMACMD5;
import net.schmizz.sshj.transport.mac.HMACMD596;
import net.schmizz.sshj.transport.mac.HMACSHA1;
import net.schmizz.sshj.transport.mac.HMACSHA196;
import net.schmizz.sshj.transport.mac.HMACSHA2256;
import net.schmizz.sshj.transport.mac.HMACSHA2512;
import net.schmizz.sshj.transport.random.BouncyCastleRandom;
import net.schmizz.sshj.transport.random.JCERandom;
import net.schmizz.sshj.transport.random.SingletonRandomFactory;
import net.schmizz.sshj.userauth.keyprovider.OpenSSHKeyFile;
import net.schmizz.sshj.userauth.keyprovider.PKCS8KeyFile;
import net.schmizz.sshj.userauth.keyprovider.PuTTYKeyFile;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.image.ByteLookupTable;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * A {@link net.schmizz.sshj.Config} that is initialized as follows. Items marked with an asterisk are added to the config only if
 * BouncyCastle is in the classpath.
 * <p/>
 * <ul>
 * <li>{@link net.schmizz.sshj.ConfigImpl#setKeyExchangeFactories Key exchange}: {@link net.schmizz.sshj.transport.kex.DHG14}*, {@link net.schmizz.sshj.transport.kex.DHG1}</li>
 * <li>{@link net.schmizz.sshj.ConfigImpl#setCipherFactories Ciphers} [1]: {@link net.schmizz.sshj.transport.cipher.AES128CTR}, {@link net.schmizz.sshj.transport.cipher.AES192CTR}, {@link net.schmizz.sshj.transport.cipher.AES256CTR},
 * {@link
 * net.schmizz.sshj.transport.cipher.AES128CBC}, {@link net.schmizz.sshj.transport.cipher.AES192CBC}, {@link net.schmizz.sshj.transport.cipher.AES256CBC}, {@link net.schmizz.sshj.transport.cipher.AES192CBC}, {@link net.schmizz.sshj.transport.cipher.TripleDESCBC}, {@link net.schmizz.sshj.transport.cipher.BlowfishCBC}</li>
 * <li>{@link net.schmizz.sshj.ConfigImpl#setMACFactories MAC}: {@link net.schmizz.sshj.transport.mac.HMACSHA1}, {@link net.schmizz.sshj.transport.mac.HMACSHA196}, {@link net.schmizz.sshj.transport.mac.HMACMD5}, {@link
 * net.schmizz.sshj.transport.mac.HMACMD596}</li>
 * <li>{@link net.schmizz.sshj.ConfigImpl#setCompressionFactories Compression}: {@link net.schmizz.sshj.transport.compression.NoneCompression}</li>
 * <li>{@link net.schmizz.sshj.ConfigImpl#setSignatureFactories Signature}: {@link net.schmizz.sshj.signature.SignatureRSA}, {@link net.schmizz.sshj.signature.SignatureDSA}</li>
 * <li>{@link net.schmizz.sshj.ConfigImpl#setRandomFactory PRNG}: {@link net.schmizz.sshj.transport.random.BouncyCastleRandom}* or {@link net.schmizz.sshj.transport.random.JCERandom}</li>
 * <li>{@link net.schmizz.sshj.ConfigImpl#setFileKeyProviderFactories Key file support}: {@link net.schmizz.sshj.userauth.keyprovider.PKCS8KeyFile}*, {@link
 * net.schmizz.sshj.userauth.keyprovider.OpenSSHKeyFile}*</li>
 * <li>{@link net.schmizz.sshj.ConfigImpl#setVersion Client version}: {@code "NET_3_0"}</li>
 * </ul>
 * <p/>
 * [1] It is worth noting that Sun's JRE does not have the unlimited cryptography extension enabled by default. This
 * prevents using ciphers with strength greater than 128.
 */
public class DefaultConfig
        extends ConfigImpl {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private static final String VERSION = "SSHJ_0_14_0";

    public DefaultConfig() {
        setVersion(VERSION);
        final boolean bouncyCastleRegistered = SecurityUtils.isBouncyCastleRegistered();
        initKeyExchangeFactories(bouncyCastleRegistered);
        initRandomFactory(bouncyCastleRegistered);
        initFileKeyProviderFactories(bouncyCastleRegistered);
        initCipherFactories();
        initCompressionFactories();
        initMACFactories();
        initSignatureFactories();
        setKeepAliveProvider(KeepAliveProvider.HEARTBEAT);
    }

    protected void initKeyExchangeFactories(boolean bouncyCastleRegistered) {
        if (bouncyCastleRegistered)
            setKeyExchangeFactories(new Curve25519SHA256.Factory(),
                    new DHGexSHA256.Factory(),
                    new ECDHNistP.Factory521(),
                    new ECDHNistP.Factory384(),
                    new ECDHNistP.Factory256(),
                    new DHGexSHA1.Factory(),
                    new DHG14.Factory(),
                    new DHG1.Factory());
        else
            setKeyExchangeFactories(new DHG1.Factory(), new DHGexSHA1.Factory());
    }

    protected void initRandomFactory(boolean bouncyCastleRegistered) {
        setRandomFactory(new SingletonRandomFactory(bouncyCastleRegistered
                ? new BouncyCastleRandom.Factory() : new JCERandom.Factory()));
    }

    protected void initFileKeyProviderFactories(boolean bouncyCastleRegistered) {
        if (bouncyCastleRegistered) {
            setFileKeyProviderFactories(new PKCS8KeyFile.Factory(), new OpenSSHKeyFile.Factory(), new PuTTYKeyFile.Factory());
        }
    }


    protected void initCipherFactories() {
        List<Factory.Named<Cipher>> avail = new LinkedList<Factory.Named<Cipher>>(Arrays.<Factory.Named<Cipher>>asList(
                new AES128CTR.Factory(),
                new AES192CTR.Factory(),
                new AES256CTR.Factory(),
                new AES128CBC.Factory(),
                new AES192CBC.Factory(),
                new AES256CBC.Factory(),
                new TripleDESCBC.Factory(),
                new BlowfishCBC.Factory(),
                BlockCiphers.BlowfishCTR(),
                BlockCiphers.Cast128CBC(),
                BlockCiphers.Cast128CTR(),
                BlockCiphers.IDEACBC(),
                BlockCiphers.IDEACTR(),
                BlockCiphers.Serpent128CBC(),
                BlockCiphers.Serpent128CTR(),
                BlockCiphers.Serpent192CBC(),
                BlockCiphers.Serpent192CTR(),
                BlockCiphers.Serpent256CBC(),
                BlockCiphers.Serpent256CTR(),
                BlockCiphers.TripleDESCTR(),
                BlockCiphers.Twofish128CBC(),
                BlockCiphers.Twofish128CTR(),
                BlockCiphers.Twofish192CBC(),
                BlockCiphers.Twofish192CTR(),
                BlockCiphers.Twofish256CBC(),
                BlockCiphers.Twofish256CTR(),
                BlockCiphers.TwofishCBC(),
                StreamCiphers.Arcfour(),
                StreamCiphers.Arcfour128(),
                StreamCiphers.Arcfour256()));

        boolean warn = false;
        // Ref. https://issues.apache.org/jira/browse/SSHD-24
        // "AES256 and AES192 requires unlimited cryptography extension"
        for (Iterator<Factory.Named<Cipher>> i = avail.iterator(); i.hasNext(); ) {
            final Factory.Named<Cipher> f = i.next();
            try {
                final Cipher c = f.create();
                final byte[] key = new byte[c.getBlockSize()];
                final byte[] iv = new byte[c.getIVSize()];
                c.init(Cipher.Mode.Encrypt, key, iv);
            } catch (Exception e) {
                warn = true;
                log.warn(e.getCause().getMessage());
                i.remove();
            }
        }
        if (warn)
            log.warn("Disabling high-strength ciphers: cipher strengths apparently limited by JCE policy");

        setCipherFactories(avail);
        log.debug("Available cipher factories: {}", avail);
    }

    protected void initSignatureFactories() {
        setSignatureFactories(new SignatureECDSA.Factory(), new SignatureRSA.Factory(), new SignatureDSA.Factory(), new SignatureEdDSA.Factory());
    }

    protected void initMACFactories() {
        setMACFactories(new HMACSHA1.Factory(), new HMACSHA196.Factory(), new HMACMD5.Factory(),
                new HMACMD596.Factory(), new HMACSHA2256.Factory(), new HMACSHA2512.Factory());
    }

    protected void initCompressionFactories() {
        setCompressionFactories(new NoneCompression.Factory());
    }


}
