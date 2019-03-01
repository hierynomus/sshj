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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.regex.Pattern;

import net.schmizz.sshj.common.Base64;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.common.SecurityUtils;

public class FingerprintVerifier implements HostKeyVerifier {
    private static final Pattern MD5_FINGERPRINT_PATTERN = Pattern.compile("[0-9a-f]{2}+(:[0-9a-f]{2}+){15}+");
    /**
     * Valid examples:
     *
     * <ul>
     * <li><code>4b:69:6c:72:6f:79:20:77:61:73:20:68:65:72:65:21</code></li>
     * <li><code>MD5:4b:69:6c:72:6f:79:20:77:61:73:20:68:65:72:65:21</code></li>
     * <li><code>SHA1:FghNYu1l/HyE/qWbdQ2mkxrd0rU</code></li>
     * <li><code>SHA1:FghNYu1l/HyE/qWbdQ2mkxrd0rU=</code></li>
     * <li><code>SHA256:l/SjyCoKP8jAx3d8k8MWH+UZG0gcuIR7TQRE/A3faQo</code></li>
     * <li><code>SHA256:l/SjyCoKP8jAx3d8k8MWH+UZG0gcuIR7TQRE/A3faQo=</code></li>
     * </ul>
     *
     *
     * @param fingerprint of an SSH fingerprint in MD5 (hex), SHA-1 (base64) or SHA-256(base64) format
     *
     * @return
     */
    public static HostKeyVerifier getInstance(String fingerprint) {

        try {
            if (fingerprint.startsWith("SHA1:")) {
                return new FingerprintVerifier("SHA-1", fingerprint.substring(5));
            }

            if (fingerprint.startsWith("SHA256:")) {
                return new FingerprintVerifier("SHA-256", fingerprint.substring(7));
            }

            final String md5;
            if (fingerprint.startsWith("MD5:")) {
                md5 = fingerprint.substring(4); // remove the MD5: prefix
            } else {
                md5 = fingerprint;
            }

            if (!MD5_FINGERPRINT_PATTERN.matcher(md5).matches()) {
                throw new SSHRuntimeException("Invalid MD5 fingerprint: " + fingerprint);
            }

            // Use the old default fingerprint verifier for md5 fingerprints
            return (new HostKeyVerifier() {
                @Override
                public boolean verify(String h, int p, PublicKey k) {
                    return SecurityUtils.getFingerprint(k).equals(md5);
                }
            });
        } catch (SSHRuntimeException e) {
            throw e;
        } catch (IOException e) {
            throw new SSHRuntimeException(e);
        }

    }

    private final String digestAlgorithm;
    private final byte[] fingerprintData;

    /**
     *
     * @param digestAlgorithm
     *            the used digest algorithm
     * @param base64Fingerprint
     *            base64 encoded fingerprint data
     *
     * @throws IOException
     */
    private FingerprintVerifier(String digestAlgorithm, String base64Fingerprint) throws IOException {
        this.digestAlgorithm = digestAlgorithm;

        // if the length is not padded with "=" chars at the end so that it is divisible by 4 the SSHJ Base64 implementation does not work correctly
        StringBuilder base64FingerprintBuilder = new StringBuilder(base64Fingerprint);
        while (base64FingerprintBuilder.length() % 4 != 0) {
            base64FingerprintBuilder.append("=");
        }
        fingerprintData = Base64.decode(base64FingerprintBuilder.toString());
    }

    @Override
    public boolean verify(String hostname, int port, PublicKey key) {
        MessageDigest digest;
        try {
            digest = SecurityUtils.getMessageDigest(digestAlgorithm);
        } catch (GeneralSecurityException e) {
            throw new SSHRuntimeException(e);
        }
        digest.update(new Buffer.PlainBuffer().putPublicKey(key).getCompactData());

        byte[] digestData = digest.digest();
        return Arrays.equals(fingerprintData, digestData);
    }

    @Override
    public String toString() {
        return "FingerprintVerifier{digestAlgorithm='" + digestAlgorithm + "'}";
    }
}