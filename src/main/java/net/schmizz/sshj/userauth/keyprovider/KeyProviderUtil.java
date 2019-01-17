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
package net.schmizz.sshj.userauth.keyprovider;

import com.hierynomus.sshj.userauth.keyprovider.OpenSSHKeyV1KeyFile;
import net.schmizz.sshj.common.IOUtils;

import java.io.*;

public class KeyProviderUtil {

    /**
     * Attempts to detect how a key file is encoded.
     * <p/>
     * Return values are consistent with the {@code NamedFactory} implementations in the {@code keyprovider} package.
     *
     * @param location
     * @return name of the key file format
     * @throws java.io.IOException
     */
    public static KeyFormat detectKeyFileFormat(File location)
            throws IOException {
        return detectKeyFileFormat(new FileReader(location),
                new File(location + ".pub").exists() || new File(location + "-cert.pub").exists());
    }

    /**
     * Attempts to detect how a key file is encoded.
     * <p/>
     * Return values are consistent with the {@code NamedFactory} implementations in the {@code keyprovider} package.
     *
     * @param privateKey     Private key stored in a string
     * @param separatePubKey Is the public key stored separately from the private key
     * @return name of the key file format
     * @throws java.io.IOException
     */
    public static KeyFormat detectKeyFileFormat(String privateKey, boolean separatePubKey)
            throws IOException {
        return detectKeyFileFormat(new StringReader(privateKey), separatePubKey);
    }

    /**
     * Attempts to detect how a key file is encoded.
     * <p/>
     * Return values are consistent with the {@code NamedFactory} implementations in the {@code keyprovider} package.
     *
     * @param privateKey     Private key accessible through a {@code Reader}
     * @param separatePubKey Is the public key stored separately from the private key
     * @return name of the key file format
     * @throws java.io.IOException
     */
    public static KeyFormat detectKeyFileFormat(Reader privateKey, boolean separatePubKey)
            throws IOException {
        String header = readHeader(privateKey);
        if (header == null) {
            throw new IOException("Empty file");
        }
        return keyFormatFromHeader(header, separatePubKey);
    }

    private static String readHeader(Reader privateKey) throws IOException {
        BufferedReader br = new BufferedReader(privateKey);
        try {
            String header;
            while ((header = br.readLine()) != null) {
                header = header.trim();
                if (!header.isEmpty()) {
                    break;
                }
            }
            return header;
        } finally {
            IOUtils.closeQuietly(br);
        }
    }

    private static KeyFormat keyFormatFromHeader(String header, boolean separatePubKey) {
        if (header.startsWith("-----BEGIN") && header.endsWith("PRIVATE KEY-----")) {
            if (header.contains(OpenSSHKeyV1KeyFile.OPENSSH_PRIVATE_KEY)) {
                return KeyFormat.OpenSSHv1;
            } else if (separatePubKey) {
                // Can delay asking for password since have unencrypted pubkey
                return KeyFormat.OpenSSH;
            } else if (header.contains("BEGIN PRIVATE KEY") || header.contains("BEGIN ENCRYPTED PRIVATE KEY")) {
                return KeyFormat.PKCS8;
            } else {
                return KeyFormat.PKCS5;
            }
        } else if (header.startsWith("PuTTY-User-Key-File-")) {
            return KeyFormat.PuTTY;
        } else {
            return KeyFormat.Unknown;
        }
    }
}
