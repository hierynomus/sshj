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

import java.io.BufferedReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

/**
 * Standard implementation of PEM Key Reader supporting Base64 decoding without decryption
 */
class StandardPEMKeyReader implements PEMKeyReader {
    private static final String HEADER_DELIMITER = "-----BEGIN";

    private static final String FOOTER_DELIMITER = "-----END";

    private static final char PEM_HEADER_DELIMITER = ':';

    private static final int CHARACTER_NOT_FOUND = -1;

    private static final String HEADER_NOT_FOUND = "header not found";

    private static final Base64.Decoder bodyDecoder = Base64.getDecoder();

    /**
     * Read PEM Key from Buffered Reader
     *
     * @param bufferedReader Buffered Reader containing lines from resource reader
     * @return PEM Key
     * @throws IOException Thrown on failure to read or decode PEM Key
     */
    @Override
    public PEMKey readPemKey(final BufferedReader bufferedReader) throws IOException {
        Objects.requireNonNull(bufferedReader, "Reader required");
        final PEMKey.PEMKeyType pemKeyType = findPemKeyType(bufferedReader);
        return readPemKeyBody(pemKeyType, bufferedReader);
    }

    private PEMKey.PEMKeyType findPemKeyType(final BufferedReader bufferedReader) throws IOException {
        PEMKey.PEMKeyType pemKeyTypeFound = null;

        String header = HEADER_NOT_FOUND;
        String line = bufferedReader.readLine();
        readLoop: while (line != null) {
            if (line.startsWith(HEADER_DELIMITER)) {
                header = line;
                for (final PEMKey.PEMKeyType pemKeyType : PEMKey.PEMKeyType.values()) {
                    if (pemKeyType.getHeader().equals(line)) {
                        pemKeyTypeFound = pemKeyType;
                        break readLoop;
                    }
                }
            }

            line = bufferedReader.readLine();
        }

        if (pemKeyTypeFound == null) {
            throw new IOException(String.format("Supported PEM Key Type not found for header [%s]", header));
        }

        return pemKeyTypeFound;
    }

    private PEMKey readPemKeyBody(final PEMKey.PEMKeyType pemKeyType, final BufferedReader bufferedReader) throws IOException {
        final StringBuilder builder = new StringBuilder();

        final List<String> headers = new ArrayList<>();

        String line = bufferedReader.readLine();
        while (line != null) {
            if (line.startsWith(FOOTER_DELIMITER)) {
                break;
            }

            if (line.indexOf(PEM_HEADER_DELIMITER) > CHARACTER_NOT_FOUND) {
                headers.add(line);
            } else if (!line.isEmpty()) {
                builder.append(line);
            }

            line = bufferedReader.readLine();
        }

        final String pemKeyBody = builder.toString();
        final byte[] pemKeyBodyDecoded = getPemKeyBodyDecoded(pemKeyBody);
        return new PEMKey(pemKeyType, headers, pemKeyBodyDecoded);
    }

    private byte[] getPemKeyBodyDecoded(final String pemKeyBodyEncoded) throws IOException {
        try {
            return bodyDecoder.decode(pemKeyBodyEncoded);
        } catch (final IllegalArgumentException e) {
            throw new IOException("Base64 decoding of PEM Key failed", e);
        }
    }
}
