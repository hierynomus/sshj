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
 */
package net.schmizz.sshj.transport.verification;

import net.schmizz.sshj.common.Base64;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.common.SecurityUtils;
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
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
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

    private static final Logger LOG = LoggerFactory.getLogger(OpenSSHKnownHosts.class);
    protected final Logger log = LoggerFactory.getLogger(getClass());

    protected final File khFile;
    protected final List<HostEntry> entries = new ArrayList<HostEntry>();

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
                        HostEntry entry = EntryFactory.parseEntry(line);
                        if (entry != null) {
                            entries.add(entry);
                        }
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

    @Override
    public boolean verify(final String hostname, final int port, final PublicKey key) {
        final KeyType type = KeyType.fromKey(key);

        if (type == KeyType.UNKNOWN)
            return false;

        final String adjustedHostname = (port != 22) ? "[" + hostname + "]:" + port : hostname;

        for (HostEntry e : entries) {
            try {
                if (e.appliesTo(type, adjustedHostname))
                    return e.verify(key) || hostKeyChangedAction(e, adjustedHostname, key);
            } catch (IOException ioe) {
                log.error("Error with {}: {}", e, ioe);
                return false;
            }
        }

        return hostKeyUnverifiableAction(adjustedHostname, key);
    }

    protected boolean hostKeyUnverifiableAction(String hostname, PublicKey key) {
        return false;
    }

    protected boolean hostKeyChangedAction(HostEntry entry, String hostname, PublicKey key) {
        log.warn("Host key for `{}` has changed!", hostname);
        return false;
    }

    public List<HostEntry> entries() {
        return entries;
    }

    private static final String LS = System.getProperty("line.separator");

    public void write()
            throws IOException {
        final BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(khFile));
        try {
            for (HostEntry entry : entries)
                bos.write((entry.getLine() + LS).getBytes(IOUtils.UTF8));
        } finally {
            bos.close();
        }
    }

    public static File detectSSHDir() {
        final File sshDir = new File(System.getProperty("user.home"), ".ssh");
        return sshDir.exists() ? sshDir : null;
    }


    /**
     * Each line in these files contains the following fields: markers
     * (optional), hostnames, bits, exponent, modulus, comment.  The fields are
     * separated by spaces.
     * <p/>
     * The marker is optional, but if it is present then it must be one of
     * ``@cert-authority'', to indicate that the line contains a certification
     * authority (CA) key, or ``@revoked'', to indicate that the key contained
     * on the line is revoked and must not ever be accepted.  Only one marker
     * should be used on a key line.
     * <p/>
     * Hostnames is a comma-separated list of patterns (`*' and `?' act as
     * wildcards); each pattern in turn is matched against the canonical host
     * name (when authenticating a client) or against the user-supplied name
     * (when authenticating a server).  A pattern may also be preceded by `!' to
     * indicate negation: if the host name matches a negated pattern, it is not
     * accepted (by that line) even if it matched another pattern on the line.
     * A hostname or address may optionally be enclosed within `[' and `]'
     * brackets then followed by `:' and a non-standard port number.
     * <p/>
     * Alternately, hostnames may be stored in a hashed form which hides host
     * names and addresses should the file's contents be disclosed.  Hashed
     * hostnames start with a `|' character.  Only one hashed hostname may
     * appear on a single line and none of the above negation or wildcard
     * operators may be applied.
     * <p/>
     * Bits, exponent, and modulus are taken directly from the RSA host key;
     * they can be obtained, for example, from /etc/ssh/ssh_host_key.pub.  The
     * optional comment field continues to the end of the line, and is not used.
     * <p/>
     * Lines starting with `#' and empty lines are ignored as comments.
     */
    public static class EntryFactory {

        public static HostEntry parseEntry(String line)
                throws IOException {
            if (isComment(line)) {
                return new CommentEntry(line);
            }

            final String[] split = line.split(" ");

            int i = 0;
            final Marker marker = Marker.fromString(split[i]);
            if (marker != null) {
                i++;
            }

            final String hostnames = split[i++];
            final String sType = split[i++];

            KeyType type = KeyType.fromString(sType);
            PublicKey key;

            if (type != KeyType.UNKNOWN) {
                final String sKey = split[i++];
                key = getKey(sKey);
            } else if (isBits(sType)) {
                type = KeyType.RSA;
                // int bits = Integer.valueOf(sType);
                final BigInteger e = new BigInteger(split[i++]);
                final BigInteger n = new BigInteger(split[i++]);
                try {
                    final KeyFactory keyFactory = SecurityUtils.getKeyFactory("RSA");
                    key = keyFactory.generatePublic(new RSAPublicKeySpec(n, e));
                } catch (Exception ex) {
                    LOG.error("Error reading entry `{}`, could not create key", line, ex);
                    return null;
                }
            } else {
                LOG.error("Error reading entry `{}`, could not determine type", line);
                return null;
            }

            if (isHashed(hostnames)) {
                return new HashedEntry(marker, hostnames, type, key);
            } else {
                return new SimpleEntry(marker, hostnames, type, key);
            }
        }

        private static PublicKey getKey(String sKey)
                throws IOException {
            return new Buffer.PlainBuffer(Base64.decode(sKey)).readPublicKey();
        }

        private static boolean isBits(String type) {
            try {
                Integer.parseInt(type);
                return true;
            } catch (NumberFormatException e) {
                return false;
            }
        }

        private static boolean isComment(String line) {
            return line.isEmpty() || line.startsWith("#");
        }

        public static boolean isHashed(String line) {
            return line.startsWith("|1|");
        }

    }

    public interface HostEntry {
        boolean appliesTo(KeyType type, String host)
                throws IOException;

        boolean verify(PublicKey key)
                throws IOException;

        String getLine();
    }

    public static class CommentEntry
            implements HostEntry {
        private final String comment;

        public CommentEntry(String comment) {
            this.comment = comment;
        }

        @Override
        public boolean appliesTo(KeyType type, String host) {
            return false;
        }

        @Override
        public boolean verify(PublicKey key) {
            return false;
        }

        @Override
        public String getLine() {
            return comment;
        }
    }

    public static abstract class AbstractEntry
            implements HostEntry {

        protected final OpenSSHKnownHosts.Marker marker;
        protected final KeyType type;
        protected final PublicKey key;

        public AbstractEntry(Marker marker, KeyType type, PublicKey key) {
            this.marker = marker;
            this.type = type;
            this.key = key;
        }

        @Override
        public boolean verify(PublicKey key)
                throws IOException {
            return key.equals(this.key) && marker != Marker.REVOKED;
        }

        public String getLine() {
            final StringBuilder line = new StringBuilder();

            if (marker != null) line.append(marker.getMarkerString()).append(" ");

            line.append(getHostPart());
            line.append(" ").append(type.toString());
            line.append(" ").append(getKeyString());
            return line.toString();
        }

        private String getKeyString() {
            final Buffer.PlainBuffer buf = new Buffer.PlainBuffer().putPublicKey(key);
            return Base64.encodeBytes(buf.array(), buf.rpos(), buf.available());
        }

        protected abstract String getHostPart();
    }

    public static class SimpleEntry
            extends AbstractEntry {
        private final List<String> hosts;
        private final String hostnames;

        public SimpleEntry(Marker marker, String hostnames, KeyType type, PublicKey key) {
            super(marker, type, key);
            this.hostnames = hostnames;
            hosts = Arrays.asList(hostnames.split(","));
        }

        @Override
        protected String getHostPart() {
            return hostnames;
        }

        @Override
        public boolean appliesTo(KeyType type, String host)
                throws IOException {
            return type == this.type && hostnames.contains(host);
        }
    }

    public static class HashedEntry
            extends AbstractEntry {
        private final MAC sha1 = new HMACSHA1();

        private final String hashedHost;
        private final String salt;

        private byte[] saltyBytes;

        public HashedEntry(Marker marker, String hash, KeyType type, PublicKey key)
                throws SSHException {
            super(marker, type, key);
            this.hashedHost = hash;
            {
                final String[] hostParts = hashedHost.split("\\|");
                if (hostParts.length != 4)
                    throw new SSHException("Unrecognized format for hashed hostname");
                salt = hostParts[2];
            }
        }

        @Override
        public boolean appliesTo(KeyType type, String host)
                throws IOException {
            return this.type == type && hashedHost.equals(hashHost(host));
        }

        private String hashHost(String host)
                throws IOException {
            sha1.init(getSaltyBytes());
            return "|1|" + salt + "|" + Base64.encodeBytes(sha1.doFinal(host.getBytes(IOUtils.UTF8)));
        }

        private byte[] getSaltyBytes()
                throws IOException {
            if (saltyBytes == null) {
                saltyBytes = Base64.decode(salt);
            }
            return saltyBytes;
        }

        @Override
        public String getLine() {
            return null;
        }

        @Override
        protected String getHostPart() {
            return hashedHost;
        }
    }

    public enum Marker {
        CA_CERT("@cert-authority"),
        REVOKED("@revoked");

        private final String sMarker;

        Marker(String sMarker) {
            this.sMarker = sMarker;
        }

        public String getMarkerString() {
            return sMarker;
        }
        
        public static Marker fromString(String str) {
            for (Marker m: values())
                if (m.sMarker.equals(str))
                    return m;
            return null;
        }
        
    }

}