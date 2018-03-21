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
package com.hierynomus.sshj.transport.verification

import net.schmizz.sshj.common.Base64
import net.schmizz.sshj.common.Buffer
import net.schmizz.sshj.transport.verification.OpenSSHKnownHosts
import org.junit.Rule
import org.junit.rules.TemporaryFolder
import spock.lang.Specification
import spock.lang.Unroll

import static org.hamcrest.CoreMatchers.equalTo
import static org.hamcrest.CoreMatchers.instanceOf
import static org.junit.Assert.assertThat
import static org.junit.Assert.assertThat

class OpenSSHKnownHostsSpec extends Specification {

    @Rule
    TemporaryFolder folder

    def "should check all host entries for key"() {
        given:
        def f = knownHosts("""
host1 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCiYp2IDgzDFhl8T4TRLIhEljvEixz1YN0XWh4dYh0REGK9T4QKiyb28EztPMdcOtz1uyX5rUGYXX9hj99S4SiU=
host1 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLTjA7hduYGmvV9smEEsIdGLdghSPD7kL8QarIIOkeXmBh+LTtT/T1K+Ot/rmXCZsP8hoUXxbvN+Tks440Ci0ck=
""")
        def pk = new Buffer.PlainBuffer(Base64.decode("AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLTjA7hduYGmvV9smEEsIdGLdghSPD7kL8QarIIOkeXmBh+LTtT/T1K+Ot/rmXCZsP8hoUXxbvN+Tks440Ci0ck=")).readPublicKey()
        when:
        def knownhosts = new OpenSSHKnownHosts(f)

        then:
        knownhosts.verify("host1", 22, pk)
    }

    def "should not fail on bad base64 entry"() {
        given:
        def f = knownHosts("""
host1 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTIDgzDFhl8T4TRLIhEljvEixz1YN0XWh4dYh0REGK9T4QKiyb28EztPMdcOtz1uyX5rUGYXX9hj99S4SiU=
host1 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLTjA7hduYGmvV9smEEsIdGLdghSPD7kL8QarIIOkeXmBh+LTtT/T1K+Ot/rmXCZsP8hoUXxbvN+Tks440Ci0ck=
""")
        def pk = new Buffer.PlainBuffer(Base64.decode("AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLTjA7hduYGmvV9smEEsIdGLdghSPD7kL8QarIIOkeXmBh+LTtT/T1K+Ot/rmXCZsP8hoUXxbvN+Tks440Ci0ck=")).readPublicKey()
        when:
        def knownhosts = new OpenSSHKnownHosts(f)

        then:
        knownhosts.verify("host1", 22, pk)
    }

    def "should mark bad line and not fail"() {
        given:
        def f = knownHosts("M36Lo+Ik5ukNugvvoNFlpnyiHMmtKxt3FpyEfYuryXjNqMNWHn/ARVnpUIl5jRLTB7WBzyLYMG7X5nuoFL9zYqKGtHxChbDunxMVbspw5WXI9VN+qxcLwmITmpEvI9ApyS/Ox2ZyN7zw==\n")

        when:
        def knownhosts = new OpenSSHKnownHosts(f)

        then:
        knownhosts.entries().size() == 1
        knownhosts.entries().get(0) instanceof OpenSSHKnownHosts.BadHostEntry
    }

    @Unroll
    def "should add comment for #type line"() {
        given:
        def f = knownHosts(s)

        when:
        def knownHosts = new OpenSSHKnownHosts(f)

        then:
        knownHosts.entries().size() == 1
        knownHosts.entries().get(0) instanceof OpenSSHKnownHosts.CommentEntry

        where:
        type << ["empty", "comment"]
        s << ["\n", "#comment\n"]
    }

    @Unroll
    def "should match any host name from multi-host line"() {
        given:
        def f = knownHosts("schmizz.net,69.163.155.180 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6P9Hlwdahh250jGZYKg2snRq2j2lFJVdKSHyxqbJiVy9VX9gTkN3K2MD48qyrYLYOyGs3vTttyUk+cK++JMzURWsrP4piby7LpeOT+3Iq8CQNj4gXZdcH9w15Vuk2qS11at6IsQPVHpKD9HGg9//EFUccI/4w06k4XXLm/IxOGUwj6I2AeWmEOL3aDi+fe07TTosSdLUD6INtR0cyKsg0zC7Da24ixoShT8Oy3x2MpR7CY3PQ1pUVmvPkr79VeA+4qV9F1JM09WdboAMZgWQZ+XrbtuBlGsyhpUHSCQOya+kOJ+bYryS+U7A+6nmTW3C9FX4FgFqTF89UHOC7V0zZQ==")
        def pk = new Buffer.PlainBuffer(Base64.decode("AAAAB3NzaC1yc2EAAAABIwAAAQEA6P9Hlwdahh250jGZYKg2snRq2j2lFJVdKSHyxqbJiVy9VX9gTkN3K2MD48qyrYLYOyGs3vTttyUk+cK++JMzURWsrP4piby7LpeOT+3Iq8CQNj4gXZdcH9w15Vuk2qS11at6IsQPVHpKD9HGg9//EFUccI/4w06k4XXLm/IxOGUwj6I2AeWmEOL3aDi+fe07TTosSdLUD6INtR0cyKsg0zC7Da24ixoShT8Oy3x2MpR7CY3PQ1pUVmvPkr79VeA+4qV9F1JM09WdboAMZgWQZ+XrbtuBlGsyhpUHSCQOya+kOJ+bYryS+U7A+6nmTW3C9FX4FgFqTF89UHOC7V0zZQ==")).readPublicKey()

        when:
        def knownHosts = new OpenSSHKnownHosts(f)

        then:
        knownHosts.verify(h, 22, pk)

        where:
        h << ["schmizz.net", "69.163.155.180"]
    }

    def knownHosts(String s) {
        def f = folder.newFile("known_hosts")
        f.write(s)
        return f
    }
}
