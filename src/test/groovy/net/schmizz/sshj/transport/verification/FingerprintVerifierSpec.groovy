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

import net.schmizz.sshj.common.Buffer
import spock.lang.Specification
import spock.lang.Unroll

class FingerprintVerifierSpec extends Specification {

    @Unroll
    def "should accept #digest fingerprints"() {
        given:
        def verifier = FingerprintVerifier.getInstance(fingerprint)
        expect:
        verifier.verify("", 0, getPublicKey())
        where:
        digest << ["SHA-1", "SHA-256", "MD5", "old style"]
        fingerprint << ["SHA1:2Fo8c/96zv32xc8GZWbOGYOlRak=",
                         "SHA256:oQGbQTujGeNIgh0ONthcEpA/BHxtt3rcYY+NxXTxQjs=",
                         "MD5:d3:5e:40:72:db:08:f1:6d:0c:d7:6d:35:0d:ba:7c:32",
                         "d3:5e:40:72:db:08:f1:6d:0c:d7:6d:35:0d:ba:7c:32"]
    }

    @Unroll
    def "should accept too short #digest fingerprints"() {
        given:
        def verifier = FingerprintVerifier.getInstance(fingerprint)
        expect:
        verifier.verify("", 0, getPublicKey())
        where:
        digest << ["SHA-1", "SHA-256"]
        fingerprint << ["SHA1:2Fo8c/96zv32xc8GZWbOGYOlRak",
                        "SHA256:oQGbQTujGeNIgh0ONthcEpA/BHxtt3rcYY+NxXTxQjs"]

    }

    def "should produce meaningful toString()"() {
        given:
        def verifier = FingerprintVerifier.getInstance("SHA1:2Fo8c/96zv32xc8GZWbOGYOlRak")

        when:
        def toStringValue = verifier.toString()

        then:
        toStringValue == "FingerprintVerifier{digestAlgorithm='SHA-1'}"
    }

    def getPublicKey() {
        def lines = new File("src/test/resources/keytypes/test_ed25519.pub").readLines()
        def keystring = lines[0].split(" ")[1]
        return new Buffer.PlainBuffer(Base64.getDecoder().decode(keystring)).readPublicKey()
    }
}
