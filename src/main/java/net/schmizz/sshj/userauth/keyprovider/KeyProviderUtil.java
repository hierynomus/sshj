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
package net.schmizz.sshj.userauth.keyprovider;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;

import net.schmizz.sshj.common.IOUtils;

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
                new File(location + ".pub").exists());
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
    public static KeyFormat detectKeyFileFormat(String privateKey,
                                                             boolean separatePubKey)
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
    public static KeyFormat detectKeyFileFormat(Reader privateKey,
                                                             boolean separatePubKey)
            throws IOException {
        BufferedReader br = new BufferedReader(privateKey);
        final String firstLine;
        try {
            firstLine = br.readLine();
        }
        finally {
            IOUtils.closeQuietly(br);
        }
        if(firstLine == null) {
            throw new IOException("Empty file");
        }
        if(firstLine.startsWith("-----BEGIN") && firstLine.endsWith("PRIVATE KEY-----")) {
            if(separatePubKey)
            // Can delay asking for password since have unencrypted pubkey
            {
                return KeyFormat.OpenSSH;
            }
            else
            // More general
            {
                return KeyFormat.PKCS8;
            }
        }
        if(firstLine.startsWith("PuTTY-User-Key-File-")) {
            return KeyFormat.PuTTY;
        }
        return KeyFormat.Unknown;
    }
}
