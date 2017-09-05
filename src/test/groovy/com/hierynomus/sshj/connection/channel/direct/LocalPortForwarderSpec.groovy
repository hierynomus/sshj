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
package com.hierynomus.sshj.connection.channel.direct

import com.hierynomus.sshj.test.SshFixture
import net.schmizz.sshj.connection.channel.direct.LocalPortForwarder
import org.junit.Rule
import spock.lang.Specification
import spock.util.concurrent.PollingConditions

import java.util.concurrent.CountDownLatch

class LocalPortForwarderSpec extends Specification {
  @Rule
  SshFixture tunnelFixture = new SshFixture()

  @Rule
  SshFixture realServer = new SshFixture()

  def "should not hang when disconnect tunnel"() {
    given:
    def client = tunnelFixture.setupConnectedDefaultClient()
    client.authPassword("test", "test")
    def socket = new ServerSocket(0)
    def lpf = client.newLocalPortForwarder(new LocalPortForwarder.Parameters("localhost", socket.getLocalPort(), "localhost", realServer.server.port), socket)
    def thread = new Thread(new Runnable() {
      @Override
      void run() {
        lpf.listen()
      }
    })

    when:
    thread.start()

    then:
    new PollingConditions().eventually {
      lpf.isRunning()
    }
    thread.isAlive()

    when:
    lpf.close()

    then:
    socket.isClosed()
  }
}
