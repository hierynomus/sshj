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
package net.schmizz.sshj;

import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.signature.Signature;
import net.schmizz.sshj.transport.cipher.Cipher;
import net.schmizz.sshj.transport.compression.Compression;
import net.schmizz.sshj.transport.kex.KeyExchange;
import net.schmizz.sshj.transport.mac.MAC;
import net.schmizz.sshj.transport.random.Random;
import net.schmizz.sshj.userauth.keyprovider.FileKeyProvider;

import java.util.Arrays;
import java.util.List;


public class ConfigImpl
        implements Config {

    private String version;

    private Factory<Random> randomFactory;

    private List<Factory.Named<KeyExchange>> kexFactories;
    private List<Factory.Named<Cipher>> cipherFactories;
    private List<Factory.Named<Compression>> compressionFactories;
    private List<Factory.Named<MAC>> macFactories;
    private List<Factory.Named<Signature>> signatureFactories;
    private List<Factory.Named<FileKeyProvider>> fileKeyProviderFactories;

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
    public List<Factory.Named<Signature>> getSignatureFactories() {
        return signatureFactories;
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

    public void setSignatureFactories(Factory.Named<Signature>... signatureFactories) {
        setSignatureFactories(Arrays.asList(signatureFactories));
    }

    @Override
    public void setSignatureFactories(List<Factory.Named<Signature>> signatureFactories) {
        this.signatureFactories = signatureFactories;
    }

    @Override
    public void setVersion(String version) {
        this.version = version;
    }

}