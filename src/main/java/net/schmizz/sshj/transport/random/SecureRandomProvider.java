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
package net.schmizz.sshj.transport.random;

import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SecureRandomProvider implements Random{
    private static final Logger logger = LoggerFactory.getLogger(SecureRandomProvider.class);

    private byte[] tmp = new byte[16];
    private SecureRandom random;

    protected SecureRandomProvider() {
        this.random = newRandom();
    }

    protected SecureRandomProvider(String algorithm, String provider) {
        this.random = newRandom(algorithm, provider);
    }

    private static SecureRandom newRandom() {
        return new SecureRandom();
    }

    private static SecureRandom newRandom(String algorithm, String provider) {
        logger.info("Generating random seed from SecureRandom of {}.", provider);
        long t = System.currentTimeMillis();
        try {
            // Use SecureRandom with the provider
            return SecureRandom.getInstance(algorithm, provider);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(String.format("%s provider is not in the classpath", provider), e);
        } catch (Exception e) {
            throw new RuntimeException(String.format("Failed to initialize SecureRandom with %s provider", provider), e);
        } finally {
            logger.debug("Creating random seed took {} ms", System.currentTimeMillis() - t);
        }
    }

    @Override
    public synchronized void fill(byte[] bytes, int start, int len) {
        if (start == 0 && len == bytes.length) {
            random.nextBytes(bytes);
        } else {
            synchronized (this) {
                if (len > tmp.length) tmp = new byte[len];
                random.nextBytes(tmp);
                System.arraycopy(tmp, 0, bytes, start, len);
            }
        }
    }

    @Override
    public void fill(byte[] bytes) {
        random.nextBytes(bytes);
    }

}
