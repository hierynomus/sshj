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

import net.schmizz.keepalive.KeepAliveProvider;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.common.LoggerFactory;
import net.schmizz.sshj.signature.Signature;
import net.schmizz.sshj.transport.cipher.Cipher;
import net.schmizz.sshj.transport.compression.Compression;
import net.schmizz.sshj.transport.kex.KeyExchange;
import net.schmizz.sshj.transport.mac.MAC;
import net.schmizz.sshj.transport.random.Random;
import net.schmizz.sshj.userauth.keyprovider.FileKeyProvider;

import java.util.List;

/**
 * Holds configuration information and factories. Acts a container for factories of {@link KeyExchange}, {@link Cipher},
 * {@link Compression}, {@link MAC}, {@link Signature}, {@link Random}, and {@link FileKeyProvider}.
 */
public interface Config {

    /**
     * Retrieve the list of named factories for {@code Cipher}.
     *
     * @return a list of named {@code Cipher} factories
     */
    List<Factory.Named<Cipher>> getCipherFactories();

    /**
     * Retrieve the list of named factories for {@code Compression}.
     *
     * @return a list of named {@code Compression} factories
     */
    List<Factory.Named<Compression>> getCompressionFactories();

    /**
     * Retrieve the list of named factories for {@code FileKeyProvider}.
     *
     * @return a list of named {@code FileKeyProvider} factories
     */
    List<Factory.Named<FileKeyProvider>> getFileKeyProviderFactories();

    /**
     * Retrieve the list of named factories for {@code KeyExchange}.
     *
     * @return a list of named {@code KeyExchange} factories
     */
    List<Factory.Named<KeyExchange>> getKeyExchangeFactories();

    /**
     * Retrieve the list of named factories for {@code MAC}.
     *
     * @return a list of named {@code MAC} factories
     */
    List<Factory.Named<MAC>> getMACFactories();

    /**
     * Retrieve the {@link Random} factory.
     *
     * @return the {@link Random} factory
     */
    Factory<Random> getRandomFactory();

    /**
     * Retrieve the list of named factories for {@link Signature}
     *
     * @return a list of named {@link Signature} factories
     */
    List<Factory.Named<Signature>> getSignatureFactories();

    /**
     * Returns the software version information for identification during SSH connection initialization. For example,
     * {@code "NET_3_0"}.
     */
    String getVersion();

    /**
     * Set the named factories for {@link Cipher}.
     *
     * @param cipherFactories a list of named factories
     */
    void setCipherFactories(List<Factory.Named<Cipher>> cipherFactories);

    /**
     * Set the named factories for {@link Compression}.
     *
     * @param compressionFactories a list of named factories
     */
    void setCompressionFactories(List<Factory.Named<Compression>> compressionFactories);

    /**
     * Set the named factories for {@link FileKeyProvider}.
     *
     * @param fileKeyProviderFactories a list of named factories
     */
    void setFileKeyProviderFactories(List<Factory.Named<FileKeyProvider>> fileKeyProviderFactories);

    /**
     * Set the named factories for {@link KeyExchange}.
     *
     * @param kexFactories a list of named factories
     */
    void setKeyExchangeFactories(List<Factory.Named<KeyExchange>> kexFactories);

    /**
     * Set the named factories for {@link MAC}.
     *
     * @param macFactories a list of named factories
     */
    void setMACFactories(List<Factory.Named<MAC>> macFactories);

    /**
     * Set the factory for {@link Random}.
     *
     * @param randomFactory the factory
     */
    void setRandomFactory(Factory<Random> randomFactory);

    /**
     * Set the named factories for {@link Signature}.
     *
     * @param signatureFactories a list of named factories
     */
    void setSignatureFactories(List<Factory.Named<Signature>> signatureFactories);

    /**
     * Set the software version information for identification during SSH connection initialization. For example, {@code
     * "SSHJ_0_1"}.
     *
     * @param version software version info
     */
    void setVersion(String version);

    /**
     * @return The provider that creates the keep-alive implementation of choice.
     */
    KeepAliveProvider getKeepAliveProvider();

    /**
     * Set the provider that provides the keep-alive implementation.
     * @param keepAliveProvider keep-alive provider
     */
    void setKeepAliveProvider(KeepAliveProvider keepAliveProvider);

    /**
     * Gets whether the client should first wait for a received server ident, before sending the client ident.
     * <p/>
     * <stong>NB:</stong> This is non-standard behaviour, and can potentially deadlock if the server also waits on the client ident.
     *
     * The default value is set to false.
     *
     * @return Whether to first wait for the server ident.
     */
    boolean isWaitForServerIdentBeforeSendingClientIdent();

    /**
     * Sets whether the SSH client should wait for a received server ident, before sending the client ident.
     * <p/>
     * <stong>NB:</stong> This is non-standard behaviour, and can potentially deadlock if the server also waits on the client ident.

     * @param waitForServerIdentBeforeSendingClientIdent Whether to wait for the server ident.
     */
    void setWaitForServerIdentBeforeSendingClientIdent(boolean waitForServerIdentBeforeSendingClientIdent);

    /**
     * Sets the LoggerFactory to use.
     */
    void setLoggerFactory(LoggerFactory loggerFactory);

    /**
     * @return The LoggerFactory the SSHClient will use.
     */
    LoggerFactory getLoggerFactory();
}
