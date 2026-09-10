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
package net.schmizz.sshj.connection.channel

import net.schmizz.sshj.common.LoggerFactory
import org.slf4j.LoggerFactory as Slf4jLoggerFactory
import spock.lang.Specification

class WindowSpec extends Specification {
    LoggerFactory loggerFactory = { clazz -> Slf4jLoggerFactory.getLogger(clazz) } as LoggerFactory

    def "Window constructor should reject zero maxPacketSize"() {
        when:
        new Window.Local(1024, 0, loggerFactory)

        then:
        thrown(IllegalArgumentException)
    }

    def "Window constructor should reject negative maxPacketSize"() {
        when:
        new Window.Local(1024, -1, loggerFactory)

        then:
        thrown(IllegalArgumentException)
    }

    def "Window.Local should accept valid maxPacketSize"() {
        when:
        def window = new Window.Local(1024, 1024, loggerFactory)

        then:
        window.getMaxPacketSize() == 1024
    }

    def "Window.Remote should reject zero maxPacketSize"() {
        when:
        new Window.Remote(1024, 0, 1000, loggerFactory)

        then:
        thrown(IllegalArgumentException)
    }

    def "Window.Remote should reject negative maxPacketSize"() {
        when:
        new Window.Remote(1024, -1, 1000, loggerFactory)

        then:
        thrown(IllegalArgumentException)
    }

    def "Window.Remote should accept valid maxPacketSize"() {
        when:
        def window = new Window.Remote(1024, 1024, 1000, loggerFactory)

        then:
        window.getMaxPacketSize() == 1024
    }
}
