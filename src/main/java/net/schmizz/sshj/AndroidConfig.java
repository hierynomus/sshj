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
import com.hierynomus.sshj.key.KeyAlgorithms;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.transport.random.JCERandom;
import net.schmizz.sshj.transport.random.SingletonRandomFactory;

import java.util.Arrays;

/**
 * Registers SpongyCastle as JCE provider.
 */
public class AndroidConfig
        extends DefaultConfig {

    static {
        SecurityUtils.registerSecurityProvider("org.spongycastle.jce.provider.BouncyCastleProvider");
    }


    @Override
    protected void initKeyAlgorithms() {
        setKeyAlgorithms(Arrays.<Factory.Named<KeyAlgorithm>>asList(
                KeyAlgorithms.EdDSA25519(),
                KeyAlgorithms.SSHRSA(),
                KeyAlgorithms.SSHDSA()
        ));
    }

    @Override
    protected void initRandomFactory(boolean ignored) {
        setRandomFactory(new SingletonRandomFactory(new JCERandom.Factory()));
    }

}
