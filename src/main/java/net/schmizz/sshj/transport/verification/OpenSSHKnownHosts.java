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
package net.schmizz.sshj.transport.verification;

import net.schmizz.sshj.common.Base64;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.ByteArrayUtils;
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

// TODO: allow modifications to known_hosts e.g. adding entries

/**
 * A {@link HostKeyVerifier} implementation for a {@code known_hosts} file i.e. in the format used by OpenSSH.
 * <p/>
 * Hashed hostnames are correctly handled.
 *
 * @see <a href="http://nms.lcs.mit.edu/projects/ssh/README.hashed-hosts">Hashed hostnames spec</a>
 */
public class OpenSSHKnownHosts
        implements HostKeyVerifier {

    private static final String LS = System.getProperty("line.separator");

    /** Represents a single line */
    public static class Entry {

        private final MAC sha1 = new HMACSHA1();

        private final List<String> hosts;
        private final KeyType type;

        private PublicKey key;
        private String sKey;

        /** Construct an entry from the hostname and public key */
        public Entry(String host, PublicKey key) {
            this.key = key;
            this.hosts = Arrays.asList(host);
            type = KeyType.fromKey(key);
        }

        /**
         * Construct an entry from a string containing the line
         *
         * @param line the line from a known_hosts file
         *
         * @throws SSHException if it could not be parsed for any reason
         */
        public Entry(String line)
                throws SSHException {
            String[] parts = line.split(" ");
            if (parts.length != 3)
                throw new SSHException("Line parts not 3: " + line);
            hosts = Arrays.asList(parts[0].split(","));
            type = KeyType.fromString(parts[1]);
            if (type == KeyType.UNKNOWN)
                throw new SSHException("Unknown key type: " + parts[1]);
            sKey = parts[2];
        }

        /** Checks whether this entry is applicable to some {@code hostname} */
        public boolean appliesTo(String hostname)
                throws IOException {
            if (!hosts.isEmpty() && hosts.get(0).startsWith("|1|")) { // Hashed hostname
                final String[] splitted = hosts.get(0).split("\\|");
                if (splitted.length != 4)
                    return false;

                final byte[] salt = Base64.decode(splitted[2]);
                if (salt.length != 20)
                    return false;
                sha1.init(salt);

                final byte[] host = Base64.decode(splitted[3]);
                if (ByteArrayUtils.equals(host, sha1.doFinal(hostname.getBytes())))
                    return true;
            } else
                // Un-hashed, possibly comma-delimited
                for (String host : hosts)
                    if (host.equals(hostname))
                        return true;
            return false;
        }

        /**
         * Returns the public host key represented in this entry.
         * <p/>
         * The key is cached so repeated calls to this method may be made without concern.
         *
         * @return the host key
         */
        public PublicKey getKey() {
            if (key == null) {
                byte[] decoded;
                try {
                    decoded = Base64.decode(sKey);
                } catch (IOException e) {
                    return null;
                }
                key = new Buffer.PlainBuffer(decoded).readPublicKey();
            }
            return key;
        }

        public KeyType getType() {
            return type;
        }

        public String getLine() {
            StringBuilder line = new StringBuilder();
            for (String host : hosts) {
                if (line.length() > 0)
                    line.append(",");
                line.append(host);
            }
            line.append(" ").append(type.toString());
            line.append(" ").append(getKeyString());
            return line.toString();
        }

        private String getKeyString() {
            if (sKey == null) {
                final Buffer.PlainBuffer buf = new Buffer.PlainBuffer().putPublicKey(key);
                sKey = Base64.encodeBytes(buf.array(), buf.rpos(), buf.available());
            }
            return sKey;
        }

        @Override
        public String toString() {
            return "Entry{hostnames=" + hosts + "; type=" + type + "; key=" + getKey() + "}";
        }

    }

    private final Logger log = LoggerFactory.getLogger(getClass());

    protected final File khFile;
    protected final List<Entry> entries = new ArrayList<Entry>();

    /**
     * Constructs a {@code KnownHosts} object from a file location
     *
     * @param khFile the file location
     *
     * @throws IOException if there is an error reading the file
     */
    public OpenSSHKnownHosts(File khFile)
            throws IOException {
        this.khFile = khFile;
        if (khFile.exists()) {
            BufferedReader br = new BufferedReader(new FileReader(khFile));
            String line;
            try {
                // Read in the file, storing each line as an entry
                while ((line = br.readLine()) != null)
                    try {
                        entries.add(new Entry(line));
                    } catch (SSHException ignore) {
                        log.debug("Bad line ({}): {} ", ignore.toString(), line);
                    }
            } finally {
                IOUtils.closeQuietly(br);
            }
        }
    }

    /**
     * Checks whether the specified host is known per the contents of the {@code known_hosts} file.
     *
     * @return {@code true} on successful verification or {@code false} on failure
     */
    public boolean verify(final String hostname, final int port, final PublicKey key) {
        KeyType type = KeyType.fromKey(key);
        if (type == KeyType.UNKNOWN)
            return false;

        final String adjustedHostname = (port != 22) ? "[" + hostname + "]:" + port : hostname;

        for (Entry e : entries)
            try {
                if (e.getType() == type && e.appliesTo(adjustedHostname))
                    if (key.equals(e.getKey()))
                        return true;
                    else {
                        return hostKeyChangedAction(e, adjustedHostname, key);
                    }
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

    public void write()
            throws IOException {
        BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(khFile));
        for (Entry entry : entries)
            bos.write((entry.getLine() + LS).getBytes());
        bos.close();
    }

    public static File detectSSHDir() {
        final File sshDir = new File(System.getProperty("user.home"), ".ssh");
        return sshDir.exists() ? sshDir : null;
    }

}
