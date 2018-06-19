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
package net.schmizz.sshj.xfer

import spock.lang.Specification

class FileSystemFileSpec extends Specification {

    def "should get child path"() {
        given:
        def file = new FileSystemFile("foo")

        when:
        def child = file.getChild("bar")

        then:
        child.getName() == "bar"
    }

    def "should not traverse higher than original path when getChild is called"() {
        given:
        def file = new FileSystemFile("foo")

        when:
        file.getChild("bar/.././foo/../../")

        then:
        thrown(IllegalArgumentException.class)
    }

    def "should ignore double slash (empty path component)"() {
        given:
        def file = new FileSystemFile("foo")

        when:
        def child = file.getChild("bar//etc/passwd")

        then:
        child.getFile().getPath().replace('\\', '/') endsWith "foo/bar/etc/passwd"
    }
}
