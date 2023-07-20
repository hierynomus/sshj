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

import net.schmizz.sshj.common.SecurityUtils;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Optional;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class DefaultSecurityProviderConfigTest {

    private static Provider bouncyCastleProvider;

    @BeforeAll
    public static void removeProviders() {
        bouncyCastleProvider = Security.getProvider(SecurityUtils.BOUNCY_CASTLE);
        if (bouncyCastleProvider != null) {
            Security.removeProvider(SecurityUtils.BOUNCY_CASTLE);
        }
    }

    @AfterAll
    public static void addProviders() {
        if (bouncyCastleProvider != null) {
            Security.addProvider(bouncyCastleProvider);
        }
    }

    @Test
    public void testBouncyCastleNotRegistered() {
        new DefaultSecurityProviderConfig();

        assertBouncyCastleNotRegistered();
    }

    private void assertBouncyCastleNotRegistered() {
        final Optional<String> bouncyCastleFound = Arrays.stream(Security.getProviders())
                .map(Provider::getName)
                .filter(SecurityUtils.BOUNCY_CASTLE::contentEquals)
                .findFirst();

        assertFalse(bouncyCastleFound.isPresent());
    }
}
