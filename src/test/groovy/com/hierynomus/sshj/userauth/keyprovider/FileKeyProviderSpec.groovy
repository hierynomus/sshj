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
package com.hierynomus.sshj.userauth.keyprovider

import com.hierynomus.sshj.test.SshServerExtension
import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.userauth.keyprovider.KeyFormat
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator
import org.junit.jupiter.api.extension.RegisterExtension
import spock.lang.Specification
import spock.lang.Unroll

class FileKeyProviderSpec extends Specification {
  @RegisterExtension
  SshServerExtension fixture = new SshServerExtension(false)

  def setup() {
    fixture.getServer().setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE)
    fixture.start()
  }

  def cleanup() {
    fixture.stopServer()
  }

  @Unroll
  def "should have #format FileKeyProvider enabled by default"() {
    given:
    // `fixture` is backed by Apache SSHD server. Looks like it doesn't support rsa-sha2-512 public key signature.
    // Changing the default config to prioritize the former default implementation of RSA signature.
    def config = new DefaultConfig()
    config.prioritizeSshRsaKeyAlgorithm()

    and:
    SSHClient client = fixture.setupClient(config)
    fixture.connectClient(client)

    when:
    client.authPublickey("jeroen", keyfile)

    then:
    client.isAuthenticated()

    cleanup:
    client?.disconnect()

    where:
    format | keyfile
    KeyFormat.PKCS8 | "src/test/resources/keyformats/pkcs8"
    KeyFormat.OpenSSH | "src/test/resources/keyformats/openssh"
  }
}
