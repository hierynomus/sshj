/*
 * Copyright 2010 Shikhar Bhushan
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
package net.schmizz.sshj.transport.verification;

import net.schmizz.sshj.common.Base64;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.transport.mac.HMACSHA1;
import net.schmizz.sshj.transport.mac.MAC;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A {@link HostKeyVerifier} implementation for a {@code known_hosts} file i.e. in the format used by OpenSSH.
 *
 * @see <a href="http://nms.lcs.mit.edu/projects/ssh/README.hashed-hosts">Hashed hostnames spec</a>
 */
public class OpenSSHKnownHosts
        implements HostKeyVerifier {

    public static abstract class Entry {

        private KeyType type;
        private PublicKey key;
        private String sKey;

        protected void init(PublicKey key)
                throws SSHException {
            this.key = key;
            this.type = KeyType.fromKey(key);
            if (type == KeyType.UNKNOWN)
                throw new SSHException("Unknown key type for key: " + key);
        }

        protected void init(String typeString, String keyString)
                throws SSHException {
            this.sKey = keyString;
            this.type = KeyType.fromString(typeString);
            if (type == KeyType.UNKNOWN)
                throw new SSHException("Unknown key type: " + typeString);
        }

        public KeyType getType() {
            return type;
        }

        public PublicKey getKey()
                throws IOException {
            if (key == null) {
                key = new Buffer.PlainBuffer(Base64.decode(sKey)).readPublicKey();
            }
            return key;
        }

        protected String getKeyString() {
            if (sKey == null) {
                final Buffer.PlainBuffer buf = new Buffer.PlainBuffer().putPublicKey(key);
                sKey = Base64.encodeBytes(buf.array(), buf.rpos(), buf.available());
            }
            return sKey;
        }

        public String getLine() {
            final StringBuilder line = new StringBuilder();
            line.append(getHostPart());
            line.append(" ").append(type.toString());
            line.append(" ").append(getKeyString());
            return line.toString();
        }

        @Override
        public String toString() {
            return "KnownHostsEntry{host=" + getHostPart() + "; type=" + type + "}";
        }

        protected abstract String getHostPart();

        public abstract boolean appliesTo(String host)
                throws IOException;

    }

    public static class SimpleEntry
            extends Entry {

        private final List<String> hosts;

        public SimpleEntry(String host, PublicKey key)
                throws SSHException {
            this(Arrays.asList(host), key);
        }

        public SimpleEntry(List<String> hosts, PublicKey key)
                throws SSHException {
            this.hosts = hosts;
            init(key);
        }

        public SimpleEntry(String line)
                throws SSHException {
            final String[] parts = line.split(" ");
            if (parts.length != 3)
                throw new SSHException("Line parts not 3: " + line);
            hosts = Arrays.asList(parts[0].split(","));
            init(parts[1], parts[2]);
        }

        public boolean appliesTo(String host) {
            for (String h : hosts)
                if (host.equals(h))
                    return true;
            return false;
        }

        protected String getHostPart() {
            final StringBuilder sb = new StringBuilder();
            for (String host : hosts) {
                if (sb.length() > 0) // a host already in there
                    sb.append(",");
                sb.append(host);
            }
            return sb.toString();
        }

    }

    public static class HashedEntry
            extends Entry {

        private final MAC sha1 = new HMACSHA1();

        private String salt;
        private byte[] saltyBytes;

        private final String hashedHost;

        public HashedEntry(String host, PublicKey key)
                throws IOException {
            {
                saltyBytes = new byte[sha1.getBlockSize()];
                new java.util.Random().nextBytes(saltyBytes);
            }
            this.hashedHost = hashHost(host);
            init(key);
        }

        public HashedEntry(String line)
                throws IOException {
            final String[] parts = line.split(" ");
            if (parts.length != 3)
                throw new SSHException("Line parts not 3: " + line);
            hashedHost = parts[0];
            {
                final String[] hostParts = hashedHost.split("\\|");
                if (hostParts.length != 4)
                    throw new SSHException("Unrecognized format for hashed hostname");
                salt = hostParts[2];
            }
            init(parts[1], parts[2]);
        }

        public boolean appliesTo(String host)
                throws IOException {
            return hashedHost.equals(hashHost(host));
        }

        private String hashHost(String host)
                throws IOException {
            sha1.init(getSaltyBytes());
            return "|1|" + getSalt() + "|" + Base64.encodeBytes(sha1.doFinal(host.getBytes()));
        }

        private byte[] getSaltyBytes()
                throws IOException {
            if (saltyBytes == null) {
                saltyBytes = Base64.decode(salt);
            }
            return saltyBytes;
        }

        private String getSalt()
                throws IOException {
            if (salt == null) {
                salt = Base64.encodeBytes(saltyBytes);
            }
            return salt;
        }

        protected String getHostPart() {
            return hashedHost;
        }

    }

    protected final Logger log = LoggerFactory.getLogger(getClass());

    protected final File khFile;
    protected final List<Entry> entries = new ArrayList<Entry>();

    public OpenSSHKnownHosts(File khFile)
            throws IOException {
        this.khFile = khFile;
        if (khFile.exists()) {
            final BufferedReader br = new BufferedReader(new FileReader(khFile));
            try {
                // Read in the file, storing each line as an entry
                String line;
                while ((line = br.readLine()) != null)
                    try {
                        entries.add(isHashed(line) ? new HashedEntry(line) : new SimpleEntry(line));
                    } catch (SSHException ignore) {
                        log.debug("Bad line ({}): {} ", ignore.toString(), line);
                    }
            } finally {
                IOUtils.closeQuietly(br);
            }
        }
    }

    public File getFile() {
        return khFile;
    }

    public boolean verify(final String hostname, final int port, final PublicKey key) {
        final KeyType type = KeyType.fromKey(key);
        if (type == KeyType.UNKNOWN)
            return false;

        final String adjustedHostname = (port != 22) ? "[" + hostname + "]:" + port : hostname;

        for (Entry e : entries)
            try {
                if (e.getType() == type && e.appliesTo(adjustedHostname))
                    return key.equals(e.getKey()) || hostKeyChangedAction(e, adjustedHostname, key);
            } catch (IOException ioe) {
                log.error("Error with {}: {}", e, ioe);
                return false;
            }
        return hostKeyUnverifiableAction(adjustedHostname, key);
    }

    protected boolean hostKeyUnverifiableAction(String hostname, PublicKey key) {
        return false;
    }

    protected boolean hostKeyChangedAction(Entry entry, String hostname, PublicKey key)
            throws IOException {
        log.warn("Host key for `{}` has changed!", hostname);
        return false;
    }

    public List<Entry> entries() {
        return entries;
    }

    private static final String LS = System.getProperty("line.separator");

    public void write()
            throws IOException {
        final BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(khFile));
        try {
            for (Entry entry : entries)
                bos.write((entry.getLine() + LS).getBytes());
        } finally {
            bos.close();
        }
    }

    public static File detectSSHDir() {
        final File sshDir = new File(System.getProperty("user.home"), ".ssh");
        return sshDir.exists() ? sshDir : null;
    }

    public static boolean isHashed(String line) {
        return line.startsWith("|1|");
    }

}