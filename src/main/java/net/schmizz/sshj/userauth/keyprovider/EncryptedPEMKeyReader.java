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

import com.hierynomus.sshj.common.KeyDecryptionFailedException;
import net.schmizz.sshj.common.ByteArrayUtils;
import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.PasswordUtils;
import net.schmizz.sshj.userauth.password.Resource;
import org.bouncycastle.openssl.PEMDecryptor;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PEM Key Reader implementation supporting historical password-based encryption from OpenSSL EVP_BytesToKey
 */
class EncryptedPEMKeyReader extends StandardPEMKeyReader {
    private static final String PROC_TYPE_ENCRYPTED_HEADER = "Proc-Type: 4,ENCRYPTED";

    private static final Pattern DEK_INFO_PATTERN = Pattern.compile("^DEK-Info: ([A-Z0-9\\-]+),([A-F0-9]{16,32})$");

    private static final int DEK_INFO_ALGORITHM_GROUP = 1;

    private static final int DEK_INFO_IV_GROUP = 2;

    private final PasswordFinder passwordFinder;

    private final Resource<?> resource;

    EncryptedPEMKeyReader(final PasswordFinder passwordFinder, final Resource<?> resource) {
        this.passwordFinder = Objects.requireNonNull(passwordFinder, "Password Finder required");
        this.resource = Objects.requireNonNull(resource, "Resource required");
    }

    @Override
    public PEMKey readPemKey(final BufferedReader bufferedReader) throws IOException {
        final PEMKey pemKey = super.readPemKey(bufferedReader);
        final List<String> headers = pemKey.getHeaders();

        final PEMKey processedPemKey;
        if (isEncrypted(headers)) {
            processedPemKey = readEncryptedPemKey(pemKey);
        } else {
            processedPemKey = pemKey;
        }

        return processedPemKey;
    }

    private boolean isEncrypted(final List<String> headers) {
        return headers.contains(PROC_TYPE_ENCRYPTED_HEADER);
    }

    private PEMKey readEncryptedPemKey(final PEMKey pemKey) throws IOException {
        final List<String> headers = pemKey.getHeaders();
        final DataEncryptionKeyInfo dataEncryptionKeyInfo = getDataEncryptionKeyInfo(headers);
        final byte[] pemKeyBody = pemKey.getBody();

        byte[] decryptedPemKeyBody = null;
        char[] password = passwordFinder.reqPassword(resource);
        while (password != null) {
            try {
                decryptedPemKeyBody = getDecryptedPemKeyBody(password, pemKeyBody, dataEncryptionKeyInfo);
                break;
            } catch (final KeyDecryptionFailedException e) {
                if (passwordFinder.shouldRetry(resource)) {
                    password = passwordFinder.reqPassword(resource);
                } else {
                    throw e;
                }
            }
        }

        if (decryptedPemKeyBody == null) {
            throw new KeyDecryptionFailedException("PEM Key password-based decryption failed");
        }

        return new PEMKey(pemKey.getPemKeyType(), headers, decryptedPemKeyBody);
    }

    private byte[] getDecryptedPemKeyBody(final char[] password, final byte[] pemKeyBody, final DataEncryptionKeyInfo dataEncryptionKeyInfo) throws IOException {
        final String algorithm = dataEncryptionKeyInfo.algorithm;
        try {
            final PEMDecryptorProvider pemDecryptorProvider = new BcPEMDecryptorProvider(password);
            final PEMDecryptor pemDecryptor = pemDecryptorProvider.get(algorithm);
            final byte[] initializationVector = dataEncryptionKeyInfo.initializationVector;
            return pemDecryptor.decrypt(pemKeyBody, initializationVector);
        } catch (final OperatorCreationException e) {
            throw new IOException(String.format("PEM decryption support not found for algorithm [%s]", algorithm), e);
        } catch (final PEMException e) {
            throw new KeyDecryptionFailedException(String.format("PEM Key decryption failed for algorithm [%s]", algorithm), e);
        } finally {
            PasswordUtils.blankOut(password);
        }
    }

    private DataEncryptionKeyInfo getDataEncryptionKeyInfo(final List<String> headers) throws IOException {
        DataEncryptionKeyInfo dataEncryptionKeyInfo = null;

        for (final String header : headers) {
            final Matcher matcher = DEK_INFO_PATTERN.matcher(header);
            if (matcher.matches()) {
                final String algorithm = matcher.group(DEK_INFO_ALGORITHM_GROUP);
                final String initializationVectorGroup = matcher.group(DEK_INFO_IV_GROUP);
                final byte[] initializationVector = ByteArrayUtils.parseHex(initializationVectorGroup);
                dataEncryptionKeyInfo = new DataEncryptionKeyInfo(algorithm, initializationVector);
            }
        }

        if (dataEncryptionKeyInfo == null) {
            throw new IOException("Data Encryption Key Information header [DEK-Info] not found");
        }

        return dataEncryptionKeyInfo;
    }

    private static class DataEncryptionKeyInfo {
        private final String algorithm;

        private final byte[] initializationVector;

        private DataEncryptionKeyInfo(final String algorithm, final byte[] initializationVector) {
            this.algorithm = algorithm;
            this.initializationVector = initializationVector;
        }
    }
}
