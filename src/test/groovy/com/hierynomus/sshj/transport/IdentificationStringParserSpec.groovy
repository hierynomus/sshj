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
package com.hierynomus.sshj.transport

import net.schmizz.sshj.common.Buffer
import net.schmizz.sshj.transport.TransportException
import spock.lang.Specification

class IdentificationStringParserSpec extends Specification {

    def "should parse simple identification string"() {
        given:
        def buffer = new Buffer.PlainBuffer()
        buffer.putRawBytes("SSH-2.0-OpenSSH-6.13\r\n".bytes)

        when:
        def ident = new IdentificationStringParser(buffer).parseIdentificationString()

        then:
        ident == "SSH-2.0-OpenSSH-6.13"
    }

    def "should leniently parse identification string without carriage return"() {
        given:
        def buffer = new Buffer.PlainBuffer()
        buffer.putRawBytes("SSH-2.0-OpenSSH-6.13\n".bytes)

        when:
        def ident = new IdentificationStringParser(buffer).parseIdentificationString()

        then:
        ident == "SSH-2.0-OpenSSH-6.13"
    }

    def "should not parse header lines as part of ident"() {
        given:
        def buffer = new Buffer.PlainBuffer()
        buffer.putRawBytes("header1\nheader2\r\nSSH-2.0-OpenSSH-6.13\r\n".bytes)

        when:
        def ident = new IdentificationStringParser(buffer).parseIdentificationString()

        then:
        ident == "SSH-2.0-OpenSSH-6.13"
    }

    def "should fail on too long ident string"() {
        given:
        def buffer = new Buffer.PlainBuffer()
        buffer.putRawBytes("SSH-2.0-OpenSSH-6.13 ".bytes)
        byte[] bs = new byte[255 - buffer.wpos()]
        Arrays.fill(bs, 'a'.bytes[0])
        buffer.putRawBytes(bs).putRawBytes("\r\n".bytes)

        when:
        new IdentificationStringParser(buffer).parseIdentificationString()

        then:
        thrown(TransportException.class)
    }

    def "should not fail on too long header line"() {
        given:
        def buffer = new Buffer.PlainBuffer()
        buffer.putRawBytes("header1 ".bytes)
        byte[] bs = new byte[255 - buffer.wpos()]
        new Random().nextBytes(bs)
        buffer.putRawBytes(bs).putRawBytes("\r\n".bytes)
        buffer.putRawBytes("SSH-2.0-OpenSSH-6.13\r\n".bytes)

        when:
        def ident = new IdentificationStringParser(buffer).parseIdentificationString()

        then:
        ident == "SSH-2.0-OpenSSH-6.13"
    }

    def "should not fail on very short header line"() {
        given:
        def buffer = new Buffer.PlainBuffer()
        buffer.putRawBytes("h1\n".bytes)
        buffer.putRawBytes("SSH-2.0-OpenSSH-6.13\r\n".bytes)

        when:
        def ident = new IdentificationStringParser(buffer).parseIdentificationString()

        then:
        ident == "SSH-2.0-OpenSSH-6.13"
    }
}
