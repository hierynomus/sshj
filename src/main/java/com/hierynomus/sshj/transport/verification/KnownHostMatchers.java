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
package com.hierynomus.sshj.transport.verification;

import net.schmizz.sshj.common.Base64DecodingException;
import net.schmizz.sshj.common.Base64Decoder;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.transport.mac.MAC;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

import com.hierynomus.sshj.transport.mac.Macs;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KnownHostMatchers {

    private static final Logger log = LoggerFactory.getLogger(KnownHostMatchers.class);

    public static HostMatcher createMatcher(String hostEntry) throws SSHException {
        if (hostEntry.contains(",")) {
            return new AnyHostMatcher(hostEntry);
        }
        if (hostEntry.startsWith("!")) {
            return new NegateHostMatcher(hostEntry);
        }
        if (hostEntry.startsWith("|1|")) {
            return new HashedHostMatcher(hostEntry);
        }
        if (hostEntry.contains("*") || hostEntry.contains("?")) {
            return new WildcardHostMatcher(hostEntry);
        }

        return new EquiHostMatcher(hostEntry);
    }

    public interface HostMatcher {
        boolean match(String hostname) throws IOException;
    }

    private static class EquiHostMatcher implements HostMatcher {
        private final String host;

        public EquiHostMatcher(String host) {
            this.host = host;
        }

        @Override
        public boolean match(String hostname) {
            return host.equals(hostname);
        }
    }

    private static class HashedHostMatcher implements HostMatcher {
        private final MAC sha1 = Macs.HMACSHA1().create();
        private final String hash;
        private final String salt;
        private byte[] saltyBytes;

        HashedHostMatcher(String hash) throws SSHException {
            this.hash = hash;
            final String[] hostParts = hash.split("\\|");
            if (hostParts.length != 4) {
                throw new SSHException("Unrecognized format for hashed hostname");
            }
            salt = hostParts[2];
        }

        @Override
        public boolean match(String hostname) throws IOException {
            try {
                return hash.equals(hashHost(hostname));
            } catch (Base64DecodingException err) {
                log.warn("Hostname [{}] not matched: salt decoding failed", hostname, err);
                return false;
            }
        }

        private String hashHost(String host) throws IOException, Base64DecodingException {
            sha1.init(getSaltyBytes());
            return "|1|" + salt + "|" + Base64.getEncoder().encodeToString(sha1.doFinal(host.getBytes(StandardCharsets.UTF_8)));
        }

        private byte[] getSaltyBytes() throws IOException, Base64DecodingException {
            if (saltyBytes == null) {
                saltyBytes = Base64Decoder.decode(salt);
            }
            return saltyBytes;
        }


    }

    private static class AnyHostMatcher implements HostMatcher {
        private final List<HostMatcher> matchers;

        AnyHostMatcher(String hostEntry) throws SSHException {
            matchers = new ArrayList<HostMatcher>();
            for (String subEntry : hostEntry.split(",")) {
                matchers.add(KnownHostMatchers.createMatcher(subEntry));
            }
        }

        @Override
        public boolean match(String hostname) throws IOException {
            for (HostMatcher matcher : matchers) {
                if (matcher.match(hostname)) {
                    return true;
                }
            }
            return false;
        }
    }

    private static class NegateHostMatcher implements HostMatcher {
        private final HostMatcher matcher;

        NegateHostMatcher(String hostEntry) throws SSHException {
            this.matcher = createMatcher(hostEntry.substring(1));
        }

        @Override
        public boolean match(String hostname) throws IOException {
            return !matcher.match(hostname);
        }
    }

    private static class WildcardHostMatcher implements HostMatcher {
        private final Pattern pattern;

        public WildcardHostMatcher(String hostEntry) {
            this.pattern = Pattern.compile("^" + hostEntry.replace("[", "\\[").replace("]", "\\]").replace(".", "\\.").replace("*", ".*").replace("?", ".") + "$");
        }

        @Override
        public boolean match(String hostname) throws IOException {
            return pattern.matcher(hostname).matches();
        }

        @Override
        public String toString() {
            return "WildcardHostMatcher[" + pattern + ']';
        }
    }
}
