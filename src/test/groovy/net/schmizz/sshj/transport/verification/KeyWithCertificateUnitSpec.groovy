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
package net.schmizz.sshj.transport.verification

import com.hierynomus.sshj.userauth.certificate.Certificate
import com.hierynomus.sshj.userauth.keyprovider.OpenSSHKeyFileUtil
import net.schmizz.sshj.common.Buffer
import net.schmizz.sshj.common.KeyType
import spock.lang.Specification
import spock.lang.Unroll

import java.nio.file.Files
import java.security.PublicKey
import java.util.regex.Pattern

/**
 * This is a comprehensive test for {@code @cert-authority} records in known_hosts and utilities for verifying
 * host certificates.
 *
 * Also, take a look at the integration test {@link com.hierynomus.sshj.signature.KeyWithCertificateSpec}
 * verifying that some of that host keys can be really accepted when served by sshd.
 */
class KeyWithCertificateUnitSpec extends Specification {
    private static List<String> ALL_KEYS = [
            "id_ecdsa_256_pem_signed_by_ecdsa",
            "id_ecdsa_256_pem_signed_by_ed25519",
            "id_ecdsa_256_pem_signed_by_rsa",
            "id_ecdsa_256_rfc4716_signed_by_ecdsa",
            "id_ecdsa_256_rfc4716_signed_by_ed25519",
            "id_ecdsa_256_rfc4716_signed_by_rsa",
            "id_ecdsa_384_pem_signed_by_ecdsa",
            "id_ecdsa_384_pem_signed_by_ed25519",
            "id_ecdsa_384_pem_signed_by_rsa",
            "id_ecdsa_384_rfc4716_signed_by_ecdsa",
            "id_ecdsa_384_rfc4716_signed_by_ed25519",
            "id_ecdsa_384_rfc4716_signed_by_rsa",
            "id_ecdsa_521_pem_signed_by_ecdsa",
            "id_ecdsa_521_pem_signed_by_ed25519",
            "id_ecdsa_521_pem_signed_by_rsa",
            "id_ecdsa_521_rfc4716_signed_by_ecdsa",
            "id_ecdsa_521_rfc4716_signed_by_ed25519",
            "id_ecdsa_521_rfc4716_signed_by_rsa",
            "id_ed25519_384_pem_signed_by_ecdsa",
            "id_ed25519_384_pem_signed_by_ed25519",
            "id_ed25519_384_pem_signed_by_rsa",
            "id_ed25519_384_rfc4716_signed_by_ecdsa",
            "id_ed25519_384_rfc4716_signed_by_ed25519",
            "id_ed25519_384_rfc4716_signed_by_rsa",
            "id_rsa_2048_pem_signed_by_ecdsa",
            "id_rsa_2048_pem_signed_by_ed25519",
            "id_rsa_2048_pem_signed_by_rsa",
            "id_rsa_2048_rfc4716_signed_by_ecdsa",
            "id_rsa_2048_rfc4716_signed_by_ed25519",
            "id_rsa_2048_rfc4716_signed_by_rsa",
    ]

    @Unroll
    def "accepting a cert-authority key #hostKey"() {
        given:
        File knownHosts = Files.createTempFile("known_hosts", "").toFile()
        knownHosts.deleteOnExit()

        and:
        def matcher = Pattern.compile("^.*_signed_by_([^_]+)\$").matcher(hostKey)
        assert matcher.matches()
        File caPubKey = new File("src/itest/resources/keyfiles/certificates/CA_${matcher.group(1)}.pem.pub")
        String knownHostsFileContents = "@cert-authority 127.0.0.1 " + caPubKey.getText()
        knownHosts.write(knownHostsFileContents)

        and:
        def verifier = new OpenSSHKnownHosts(knownHosts)

        and:
        def publicKey = OpenSSHKeyFileUtil
                .initPubKey(new FileReader(
                        new File("src/itest/resources/keyfiles/certificates/${hostKey}_host-cert.pub")))
                .pubKey

        when:
        boolean result = verifier.verify("127.0.0.1", 22, publicKey)

        then:
        result

        where:
        hostKey << ALL_KEYS
    }

    @Unroll
    def "verifying a valid host certificate #hostKey"() {
        given:
        def hostCertificate = (Certificate<PublicKey>) OpenSSHKeyFileUtil
                .initPubKey(new FileReader(
                        new File("src/itest/resources/keyfiles/certificates/${hostKey}_host-cert.pub")))
                .pubKey

        and:
        Buffer certRaw = new Buffer.PlainBuffer();
        certRaw.putPublicKey(hostCertificate);

        when:
        String error = KeyType.CertUtils.verifyHostCertificate(certRaw.getCompactData(), hostCertificate, "127.0.0.1")

        then:
        error == null

        where:
        hostKey << ALL_KEYS
    }

    def "verifying an invalid certificate which was valid before"() {
        given:
        def hostCertificate = (Certificate<PublicKey>) OpenSSHKeyFileUtil
                .initPubKey(new FileReader(
                        new File("src/itest/resources/keyfiles/certificates/" +
                                 "id_ed25519_384_rfc4716_signed_by_rsa_host_valid_before_past-cert.pub")))
                .pubKey

        and:
        Buffer certRaw = new Buffer.PlainBuffer();
        certRaw.putPublicKey(hostCertificate);

        when:
        String error = KeyType.CertUtils.verifyHostCertificate(certRaw.getCompactData(), hostCertificate, "127.0.0.1")

        then:
        error != null && error.startsWith("Certificate is valid before ")
    }

    def "verifying an invalid certificate which will be valid after"() {
        given:
        def hostCertificate = (Certificate<PublicKey>) OpenSSHKeyFileUtil
                .initPubKey(new FileReader(
                        new File("src/itest/resources/keyfiles/certificates/" +
                                 "id_ed25519_384_rfc4716_signed_by_rsa_host_valid_after_future-cert.pub")))
                .pubKey

        and:
        Buffer certRaw = new Buffer.PlainBuffer();
        certRaw.putPublicKey(hostCertificate);

        when:
        String error = KeyType.CertUtils.verifyHostCertificate(certRaw.getCompactData(), hostCertificate, "127.0.0.1")

        then:
        error != null && error.startsWith("Certificate is valid after ")
    }

    def "verifying an valid certificate with no principal"() {
        given:
        def hostCertificate = (Certificate<PublicKey>) OpenSSHKeyFileUtil
                .initPubKey(new FileReader(
                        new File("src/itest/resources/keyfiles/certificates/" +
                                 "id_ed25519_384_rfc4716_signed_by_rsa_host_no_principal-cert.pub")))
                .pubKey

        and:
        Buffer certRaw = new Buffer.PlainBuffer();
        certRaw.putPublicKey(hostCertificate);

        when:
        String error1 = KeyType.CertUtils.verifyHostCertificate(
                certRaw.getCompactData(), hostCertificate, "good.example.com")
        String error2 = KeyType.CertUtils.verifyHostCertificate(
                certRaw.getCompactData(), hostCertificate, "127.0.0.1")
        String error3 = KeyType.CertUtils.verifyHostCertificate(
                certRaw.getCompactData(), hostCertificate, "good.example.bad.com")

        then:
        error1 == null
        error2 == null
        error3 == null
    }

    def "verifying an valid certificate with wildcard principal"() {
        given:
        def hostCertificate = (Certificate<PublicKey>) OpenSSHKeyFileUtil
                .initPubKey(new FileReader(
                        new File("src/itest/resources/keyfiles/certificates/" +
                                 "id_ed25519_384_rfc4716_signed_by_rsa_host_principal_wildcard_example_com-cert.pub")))
                .pubKey

        and:
        Buffer certRaw = new Buffer.PlainBuffer();
        certRaw.putPublicKey(hostCertificate);

        when:
        String error1 = KeyType.CertUtils.verifyHostCertificate(
                certRaw.getCompactData(), hostCertificate, "good.example.com")
        String error2 = KeyType.CertUtils.verifyHostCertificate(
                certRaw.getCompactData(), hostCertificate, "127.0.0.1")
        String error3 = KeyType.CertUtils.verifyHostCertificate(
                certRaw.getCompactData(), hostCertificate, "good.example.bad.com")

        then:
        error1 == null
        error2 != null && error2.contains("doesn't match any of the principals")
        error3 != null && error3.contains("doesn't match any of the principals")
    }

    def "KeyType CertUtils checkPrincipals"() {
        // Based on regress/unittests/match/test.c of portable OpenSSH, commit 068dc7ef783d135e91ff954e754d2ed432e
        expect:
        KeyType.CertUtils.matchPattern("", "")
        !KeyType.CertUtils.matchPattern("", "xxx")
        !KeyType.CertUtils.matchPattern("xxx", "")
        !KeyType.CertUtils.matchPattern("xxx", "xxxx")
        !KeyType.CertUtils.matchPattern("xxxx", "xxx")
        KeyType.CertUtils.matchPattern("", "*")
        KeyType.CertUtils.matchPattern("x", "?")
        KeyType.CertUtils.matchPattern("xx", "x?")
        KeyType.CertUtils.matchPattern("x", "*")
        KeyType.CertUtils.matchPattern("xx", "x*")
        KeyType.CertUtils.matchPattern("xx", "?*")
        KeyType.CertUtils.matchPattern("xx", "**")
        KeyType.CertUtils.matchPattern("xx", "?x")
        KeyType.CertUtils.matchPattern("xx", "*x")
        !KeyType.CertUtils.matchPattern("yx", "x?")
        !KeyType.CertUtils.matchPattern("yx", "x*")
        !KeyType.CertUtils.matchPattern("xy", "?x")
        !KeyType.CertUtils.matchPattern("xy", "*x")
    }
}