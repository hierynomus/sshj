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
package com.hierynomus.sshj

import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.common.IOUtils
import net.schmizz.sshj.connection.channel.direct.Session
import spock.lang.Specification

import java.util.concurrent.*

import static org.codehaus.groovy.runtime.IOGroovyMethods.withCloseable

class ManyChannelsSpec extends Specification {

    def "should work with many channels without nonexistent channel error (GH issue #805)"() {
        given:
        SshdContainer sshd = new SshdContainer.Builder()
                .withSshdConfig("""${SshdContainer.Builder.DEFAULT_SSHD_CONFIG}
                MaxSessions 200
                """.stripMargin())
                .build()
        sshd.start()
        SSHClient client = sshd.getConnectedClient()
        client.authPublickey("sshj", "src/test/resources/id_rsa")

        when:
        List<Future<Exception>> futures = []
        ExecutorService executorService = Executors.newCachedThreadPool()

        for (int i in 0..20) {
            futures.add(executorService.submit((Callable<Exception>) {
                return execute(client)
            }))
        }
        executorService.shutdown()
        executorService.awaitTermination(1, TimeUnit.DAYS)

        then:
        futures*.get().findAll { it != null }.empty

        cleanup:
        client.close()
    }


    private static Exception execute(SSHClient sshClient) {
        try {
            for (def i in 0..100) {
                withCloseable (sshClient.startSession()) {sshSession ->
                    Session.Command sshCommand = sshSession.exec("ls -la")
                    IOUtils.readFully(sshCommand.getInputStream()).toString()
                    sshCommand.close()
                }
            }
        } catch (Exception e) {
            return e
        }
        return null
    }
}
