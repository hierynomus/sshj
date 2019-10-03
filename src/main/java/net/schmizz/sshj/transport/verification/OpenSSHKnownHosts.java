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
package net.schmizz.sshj.transport.verification;

import com.hierynomus.sshj.transport.verification.KnownHostMatchers;
import net.schmizz.sshj.common.*;
import org.slf4j.Logger;

import java.io.*;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;

/**
 * A {@link HostKeyVerifier} implementation for a {@code known_hosts} file i.e. in the format used by OpenSSH.
 *
 * @see <a href="http://nms.lcs.mit.edu/projects/ssh/README.hashed-hosts">Hashed hostnames spec</a>
 */
public class OpenSSHKnownHosts
        implements HostKeyVerifier {

    protected final Logger log;

    protected final File khFile;
    protected final List<KnownHostEntry> entries = new ArrayList<KnownHostEntry>();

    public OpenSSHKnownHosts(File khFile)
            throws IOException {
        this(khFile, LoggerFactory.DEFAULT);
    }

    public OpenSSHKnownHosts(File khFile, LoggerFactory loggerFactory)
            throws IOException {
        this.khFile = khFile;
        log = loggerFactory.getLogger(getClass());
        if (khFile.exists()) {
            final EntryFactory entryFactory = new EntryFactory();
            final BufferedReader br = new BufferedReader(new FileReader(khFile));
            try {
                // Read in the file, storing each line as an entry
                String line;
                while ((line = br.readLine()) != null) {
                    try {
                        KnownHostEntry entry = entryFactory.parseEntry(line);
                        if (entry != null) {
                            entries.add(entry);
                        }
                    } catch (SSHException ignore) {
                        log.debug("Bad line ({}): {} ", ignore.toString(), line);
                    } catch (SSHRuntimeException ignore) {
                        log.debug("Failed to process line ({}): {} ", ignore.toString(), line);
                    }
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

        if (type == KeyType.UNKNOWN) {
            return false;
        }

        final String adjustedHostname = (port != 22) ? "[" + hostname + "]:" + port : hostname;

        boolean foundApplicableHostEntry = false;
        for (KnownHostEntry e : entries) {
            try {
                if (e.appliesTo(type, adjustedHostname)) {
                    foundApplicableHostEntry = true;
                    if (e.verify(key)) {
                        return true;
                    }
                }
            } catch (IOException ioe) {
                log.error("Error with {}: {}", e, ioe);
                return false;
            }

        }
        if (foundApplicableHostEntry) {
            return hostKeyChangedAction(adjustedHostname, key);
        }

        return hostKeyUnverifiableAction(adjustedHostname, key);
    }

    protected boolean hostKeyUnverifiableAction(String hostname, PublicKey key) {
        return false;
    }

    protected boolean hostKeyChangedAction(String hostname, PublicKey key) {
        log.warn("Host key for `{}` has changed!", hostname);
        return false;
    }

    public List<KnownHostEntry> entries() {
        return entries;
    }

    private static final String LS = System.getProperty("line.separator");

    public void write()
            throws IOException {
        final BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(khFile));
        try {
            for (KnownHostEntry entry : entries)
                bos.write((entry.getLine() + LS).getBytes(IOUtils.UTF8));
        } finally {
            bos.close();
        }
    }

    /**
     * Append a single entry
     */
    public void write(KnownHostEntry entry)
            throws IOException {
        final BufferedWriter writer = new BufferedWriter(new FileWriter(khFile, true));
        try {
            writer.write(entry.getLine());
            writer.newLine();
            writer.flush();
        }
        finally {
            IOUtils.closeQuietly(writer);
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
    public class EntryFactory {
        EntryFactory() {
        }

        public KnownHostEntry parseEntry(String line)
                throws IOException {
            if (isComment(line)) {
                return new CommentEntry(line);
            }

            final String[] split = line.split("\\s+");
            if(split.length < 3) {
                log.error("Error reading entry `{}`", line);
                return new BadHostEntry(line);
            }

            int i = 0;
            if (split[i].isEmpty()) {
                i++;
            }
            final Marker marker = Marker.fromString(split[i]);
            if (marker != null) {
                i++;
            }
            if(split.length < i + 3) {
                log.error("Error reading entry `{}`", line);
                return new BadHostEntry(line);
            }
            final String hostnames = split[i++];
            final String sType = split[i++];

            KeyType type = KeyType.fromString(sType);
            PublicKey key;

            if (type != KeyType.UNKNOWN) {
                final String sKey = split[i++];
                try {
                    byte[] keyBytes = Base64.decode(sKey);
                    key = new Buffer.PlainBuffer(keyBytes).readPublicKey();
                } catch (IOException ioe) {
                    log.warn("Error decoding Base64 key bytes", ioe);
                    return new BadHostEntry(line);
                }
            } else if (isBits(sType)) {
                type = KeyType.RSA;
                // int bits = Integer.valueOf(sType);
                final BigInteger e = new BigInteger(split[i++]);
                final BigInteger n = new BigInteger(split[i++]);
                try {
                    final KeyFactory keyFactory = SecurityUtils.getKeyFactory("RSA");
                    key = keyFactory.generatePublic(new RSAPublicKeySpec(n, e));
                } catch (Exception ex) {
                    log.error("Error reading entry `{}`, could not create key", line, ex);
                    return new BadHostEntry(line);
                }
            } else {
                log.error("Error reading entry `{}`, could not determine type", line);
                return new BadHostEntry(line);
            }

            return new HostEntry(marker, hostnames, type, key);
        }

        private boolean isBits(String type) {
            try {
                Integer.parseInt(type);
                return true;
            } catch (NumberFormatException e) {
                return false;
            }
        }

        private boolean isComment(String line) {
            return line.isEmpty() || line.startsWith("#");
        }

        public boolean isHashed(String line) {
            return line.startsWith("|1|");
        }

    }

    public interface KnownHostEntry {
        KeyType getType();

        String getFingerprint();

        boolean appliesTo(String host) throws IOException;

        boolean appliesTo(KeyType type, String host) throws IOException;

        boolean verify(PublicKey key) throws IOException;

        String getLine();
    }

    public static class CommentEntry
            implements KnownHostEntry {
        private final String comment;

        public CommentEntry(String comment) {
            this.comment = comment;
        }

        @Override
        public KeyType getType() {
            return KeyType.UNKNOWN;
        }

        @Override
        public String getFingerprint() {
            return null;
        }

        @Override
        public boolean appliesTo(String host) throws IOException {
            return false;
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

    public static class HostEntry implements KnownHostEntry {

        final OpenSSHKnownHosts.Marker marker;
        private final String hostPart;
        protected final KeyType type;
        protected final PublicKey key;
        private final KnownHostMatchers.HostMatcher matcher;

        public HostEntry(Marker marker, String hostPart, KeyType type, PublicKey key) throws SSHException {
            this.marker = marker;
            this.hostPart = hostPart;
            this.type = type;
            this.key = key;
            this.matcher = KnownHostMatchers.createMatcher(hostPart);
        }

        @Override
        public KeyType getType() {
            return type;
        }

        @Override
        public String getFingerprint() {
            return SecurityUtils.getFingerprint(key);
        }

        @Override
        public boolean appliesTo(String host) throws IOException {
            return matcher.match(host);
        }

        @Override
        public boolean appliesTo(KeyType type, String host) throws IOException {
            return this.type == type && matcher.match(host);
        }

        @Override
        public boolean verify(PublicKey key) throws IOException {
            return getKeyString(key).equals(getKeyString(this.key)) && marker != Marker.REVOKED;
        }

        public String getLine() {
            final StringBuilder line = new StringBuilder();

            if (marker != null) line.append(marker.getMarkerString()).append(" ");

            line.append(getHostPart());
            line.append(" ").append(type.toString());
            line.append(" ").append(getKeyString(key));
            return line.toString();
        }

        private String getKeyString(PublicKey pk) {
            final Buffer.PlainBuffer buf = new Buffer.PlainBuffer().putPublicKey(pk);
            return Base64.encodeBytes(buf.array(), buf.rpos(), buf.available());
        }

        protected String getHostPart() {
            return hostPart;
        }
    }

    public static class BadHostEntry implements KnownHostEntry {
        private String line;

        public BadHostEntry(String line) {
            this.line = line;
        }

        @Override
        public KeyType getType() {
            return KeyType.UNKNOWN;
        }

        @Override
        public String getFingerprint() {
            return null;
        }

        @Override
        public boolean appliesTo(String host) throws IOException {
            return false;
        }

        @Override
        public boolean appliesTo(KeyType type, String host) throws IOException {
            return false;
        }

        @Override
        public boolean verify(PublicKey key) throws IOException {
            return false;
        }

        @Override
        public String getLine() {
            return line;
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
            for (Marker m: values()) {
                if (m.sMarker.equals(str)) {
                    return m;
                }
            }
            return null;
        }
    }

    @Override
    public String toString() {
        return "OpenSSHKnownHosts{khFile='" + khFile + "'}";
    }

}
