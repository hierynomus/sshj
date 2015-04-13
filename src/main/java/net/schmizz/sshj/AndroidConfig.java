/**
 * Copyright 2009 sshj contributors
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

import java.security.Provider;
import java.security.Security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.signature.SignatureDSA;
import net.schmizz.sshj.signature.SignatureRSA;
import net.schmizz.sshj.transport.random.JCERandom;
import net.schmizz.sshj.transport.random.SingletonRandomFactory;

public class AndroidConfig
        extends DefaultConfig {

    static {
        final Logger log = LoggerFactory.getLogger(AndroidConfig.class);
        SecurityUtils.setRegisterBouncyCastle(false);
        try {
            Class<?> bcpClazz = Class.forName("org.spongycastle.jce.provider.BouncyCastleProvider");
            Security.addProvider((Provider) bcpClazz.newInstance());
            SecurityUtils.setSecurityProvider("SC");
        } catch (ClassNotFoundException e) {
            log.info("SpongyCastle was not found.");
        } catch (IllegalAccessException e) {
            log.error("IllegalAccessException", e);
        } catch (InstantiationException e) {
            log.info("InstantiationException", e);
        }
    }

    // don't add ECDSA
    protected void initSignatureFactories() {
        setSignatureFactories(new SignatureRSA.Factory(), new SignatureDSA.Factory());
    }
    
    @Override
    protected void initRandomFactory(boolean ignored) {
        setRandomFactory(new SingletonRandomFactory(new JCERandom.Factory()));
    }

}
