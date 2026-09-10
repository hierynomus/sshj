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
package net.schmizz.sshj.transport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.common.Factory;
import org.junit.jupiter.api.Test;

public class ProposalTest {

    private List<String> configuredKeyAlgorithms() {
        return Factory.Named.Util.getNames(new DefaultConfig().getKeyAlgorithms());
    }

    private List<String> hostKeyAlgorithmsFor(List<String> knownHostAlgs) {
        return new Proposal(new DefaultConfig(), knownHostAlgs, false).getHostKeyAlgorithms();
    }

    @Test
    public void withoutKnownHostAlgorithmsTheConfiguredOrderIsKept() {
        assertEquals(configuredKeyAlgorithms(), hostKeyAlgorithmsFor(Collections.<String>emptyList()));
        assertEquals(configuredKeyAlgorithms(), hostKeyAlgorithmsFor(null));
    }

    @Test
    public void knownHostRsaKeyPrefersEveryRsaSignatureAlgorithmInConfiguredOrder() {
        // known_hosts stores an RSA key as "ssh-rsa" regardless of the signature algorithm the
        // server actually uses, so all three RSA signature algorithms must be preferred - and the
        // modern rsa-sha2-* variants must stay ahead of the legacy ssh-rsa (SHA-1).
        List<String> algorithms = hostKeyAlgorithmsFor(Collections.singletonList("ssh-rsa"));

        assertEquals(Arrays.asList("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"),
                onlyRsa(algorithms));
        assertEquals(Arrays.asList("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"),
                algorithms.subList(0, 3));
    }

    @Test
    public void knownHostNonRsaKeyDoesNotReorderRsaSignatureAlgorithms() {
        List<String> algorithms = hostKeyAlgorithmsFor(Collections.singletonList("ssh-ed25519"));

        assertEquals("ssh-ed25519", algorithms.get(0));
        // no spurious reordering of the RSA algorithms relative to each other
        assertEquals(Arrays.asList("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"), onlyRsa(algorithms));
        assertTrue(algorithms.containsAll(configuredKeyAlgorithms()));
    }

    @Test
    public void knownHostRsaCertificateIsMatchedByKeyType() {
        // A certificate key type is distinct from its plain key type: an "ssh-rsa-cert-v01@openssh.com"
        // known host must prefer the certificate algorithm, not the plain rsa-sha2-* / ssh-rsa ones.
        List<String> algorithms = hostKeyAlgorithmsFor(
                Collections.singletonList("ssh-rsa-cert-v01@openssh.com"));

        assertEquals("ssh-rsa-cert-v01@openssh.com", algorithms.get(0));
        assertEquals(Arrays.asList("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"), onlyRsa(algorithms));
    }

    @Test
    public void unknownKnownHostAlgorithmIsIgnored() {
        assertEquals(configuredKeyAlgorithms(),
                hostKeyAlgorithmsFor(Collections.singletonList("some-future-algorithm@openssh.com")));
    }

    private static List<String> onlyRsa(List<String> algorithms) {
        List<String> rsa = new java.util.ArrayList<>();
        for (String algorithm : algorithms) {
            if (algorithm.equals("ssh-rsa") || algorithm.startsWith("rsa-sha2-")) {
                rsa.add(algorithm);
            }
        }
        return rsa;
    }
}
