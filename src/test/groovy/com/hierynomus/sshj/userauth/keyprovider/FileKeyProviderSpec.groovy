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

import com.hierynomus.sshj.test.SshFixture
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.userauth.keyprovider.KeyFormat
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator
import org.junit.Rule
import spock.lang.Specification
import spock.lang.Unroll

class FileKeyProviderSpec extends Specification {
  @Rule
  SshFixture fixture = new SshFixture(false)

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
    SSHClient client = fixture.setupConnectedDefaultClient()

    when:
    client.authPublickey("jeroen", keyfile)

    then:
    client.isAuthenticated()

    cleanup:
    client.disconnect()

    where:
    format | keyfile
    KeyFormat.PKCS5 | "src/test/resources/keyformats/pkcs5"
    KeyFormat.OpenSSH | "src/test/resources/keyformats/openssh"
  }
}
