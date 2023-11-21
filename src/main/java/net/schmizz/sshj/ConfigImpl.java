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

import com.hierynomus.sshj.key.KeyAlgorithm;
import net.schmizz.keepalive.KeepAliveProvider;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.common.LoggerFactory;
import net.schmizz.sshj.transport.cipher.Cipher;
import net.schmizz.sshj.transport.compression.Compression;
import net.schmizz.sshj.transport.kex.KeyExchange;
import net.schmizz.sshj.transport.mac.MAC;
import net.schmizz.sshj.transport.random.Random;
import net.schmizz.sshj.userauth.keyprovider.FileKeyProvider;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


public class ConfigImpl
        implements Config {

    private String version;

    private Factory<Random> randomFactory;
    private KeepAliveProvider keepAliveProvider;

    private List<Factory.Named<KeyExchange>> kexFactories;
    private List<Factory.Named<Cipher>> cipherFactories;
    private List<Factory.Named<Compression>> compressionFactories;
    private List<Factory.Named<MAC>> macFactories;
    private List<Factory.Named<KeyAlgorithm>> keyAlgorithms;
    private List<Factory.Named<FileKeyProvider>> fileKeyProviderFactories;

    private boolean waitForServerIdentBeforeSendingClientIdent = false;
    private LoggerFactory loggerFactory;
    private boolean verifyHostKeyCertificates = true;
    // HF-982: default to 16MB buffers.
    private int maxCircularBufferSize = 16 * 1024 * 1024;

    @Override
    public List<Factory.Named<Cipher>> getCipherFactories() {
        return cipherFactories;
    }

    @Override
    public List<Factory.Named<Compression>> getCompressionFactories() {
        return compressionFactories;
    }

    @Override
    public List<Factory.Named<FileKeyProvider>> getFileKeyProviderFactories() {
        return fileKeyProviderFactories;
    }

    @Override
    public List<Factory.Named<KeyExchange>> getKeyExchangeFactories() {
        return kexFactories;
    }

    @Override
    public List<Factory.Named<MAC>> getMACFactories() {
        return macFactories;
    }

    @Override
    public Factory<Random> getRandomFactory() {
        return randomFactory;
    }

    @Override
    public String getVersion() {
        return version;
    }

    public void setCipherFactories(Factory.Named<Cipher>... cipherFactories) {
        setCipherFactories(Arrays.asList(cipherFactories));
    }

    @Override
    public void setCipherFactories(List<Factory.Named<Cipher>> cipherFactories) {
        this.cipherFactories = cipherFactories;
    }

    public void setCompressionFactories(Factory.Named<Compression>... compressionFactories) {
        setCompressionFactories(Arrays.asList(compressionFactories));
    }

    @Override
    public void setCompressionFactories(List<Factory.Named<Compression>> compressionFactories) {
        this.compressionFactories = compressionFactories;
    }

    public void setFileKeyProviderFactories(Factory.Named<FileKeyProvider>... fileKeyProviderFactories) {
        setFileKeyProviderFactories(Arrays.asList(fileKeyProviderFactories));
    }

    @Override
    public void setFileKeyProviderFactories(List<Factory.Named<FileKeyProvider>> fileKeyProviderFactories) {
        this.fileKeyProviderFactories = fileKeyProviderFactories;
    }

    public void setKeyExchangeFactories(Factory.Named<KeyExchange>... kexFactories) {
        setKeyExchangeFactories(Arrays.asList(kexFactories));
    }

    @Override
    public void setKeyExchangeFactories(List<Factory.Named<KeyExchange>> kexFactories) {
        this.kexFactories = kexFactories;
    }

    public void setMACFactories(Factory.Named<MAC>... macFactories) {
        setMACFactories(Arrays.asList(macFactories));
    }

    @Override
    public void setMACFactories(List<Factory.Named<MAC>> macFactories) {
        this.macFactories = macFactories;
    }

    @Override
    public void setRandomFactory(Factory<Random> randomFactory) {
        this.randomFactory = randomFactory;
    }

    @Override
    public void setVersion(String version) {
        this.version = version;
    }

    @Override
    public KeepAliveProvider getKeepAliveProvider() {
        return keepAliveProvider;
    }

    @Override
    public void setKeepAliveProvider(KeepAliveProvider keepAliveProvider) {
        this.keepAliveProvider = keepAliveProvider;
    }

    @Override
    public boolean isWaitForServerIdentBeforeSendingClientIdent() {
        return waitForServerIdentBeforeSendingClientIdent;
    }

    @Override
    public void setWaitForServerIdentBeforeSendingClientIdent(boolean waitForServerIdentBeforeSendingClientIdent) {
        this.waitForServerIdentBeforeSendingClientIdent = waitForServerIdentBeforeSendingClientIdent;
    }

    @Override
    public List<Factory.Named<KeyAlgorithm>> getKeyAlgorithms() {
        return keyAlgorithms;
    }

    @Override
    public void setKeyAlgorithms(List<Factory.Named<KeyAlgorithm>> keyAlgorithms) {
        this.keyAlgorithms = keyAlgorithms;
    }

    @Override
    public LoggerFactory getLoggerFactory() {
        return loggerFactory;
    }

    @Override
    public int getMaxCircularBufferSize() {
        return maxCircularBufferSize;
    }

    @Override
    public void setMaxCircularBufferSize(int maxCircularBufferSize) {
        this.maxCircularBufferSize = maxCircularBufferSize;
    }

    @Override
    public void setLoggerFactory(LoggerFactory loggerFactory) {
        this.loggerFactory = loggerFactory;
    }

    @Override
    public boolean isVerifyHostKeyCertificates() {
        return verifyHostKeyCertificates;
    }

    @Override
    public void setVerifyHostKeyCertificates(boolean value) {
        verifyHostKeyCertificates = value;
    }

    /**
     * Modern servers neglect the key algorithm ssh-rsa. OpenSSH 8.8 even dropped its support by default in favour
     * of rsa-sha2-*. However, there are legacy servers like Apache SSHD that don't support the newer replacements
     * for ssh-rsa.
     *
     * If ssh-rsa factory is in {@link #getKeyAlgorithms()}, this methods makes ssh-rsa key algorithm more preferred
     * than any of rsa-sha2-*. Otherwise, nothing happens.
     */
    public void prioritizeSshRsaKeyAlgorithm() {
        List<Factory.Named<KeyAlgorithm>> keyAlgorithms = getKeyAlgorithms();
        for (int sshRsaIndex = 0; sshRsaIndex < keyAlgorithms.size(); ++ sshRsaIndex) {
            if ("ssh-rsa".equals(keyAlgorithms.get(sshRsaIndex).getName())) {
                for (int i = 0; i < sshRsaIndex; ++i) {
                    final String algo = keyAlgorithms.get(i).getName();
                    if ("rsa-sha2-256".equals(algo) || "rsa-sha2-512".equals(algo)) {
                        keyAlgorithms = new ArrayList<>(keyAlgorithms);
                        keyAlgorithms.add(i, keyAlgorithms.remove(sshRsaIndex));
                        setKeyAlgorithms(keyAlgorithms);
                        break;
                    }
                }
                break;
            }
        }
    }
}
