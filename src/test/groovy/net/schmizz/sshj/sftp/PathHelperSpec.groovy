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
package net.schmizz.sshj.sftp

import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

class PathHelperSpec extends Specification {

    @Shared
    def pathHelper = new PathHelper(new PathHelper.Canonicalizer() {
        /**
         * Very basic, it does not try to canonicalize relative bits in the middle of a path.
         */
        @Override
        String canonicalize(String path)
                throws IOException {
            if ("" == path || "." == path || "./" == path)
                return "/home/me"
            if (".." == path || "../" == path)
                return "/home"
            return path
        }
    }, "/")


    @Unroll
    def "should correctly componentize path \"#input\""() {
        given:
        def components = pathHelper.getComponents(input)

        expect:
        components.getName() == name
        components.getParent() == parent
        components.getPath() == path

        where:
        input                          || name       | path                           | parent
        ""                             || "me"       | "/home/me"                     | "/home"
        "/"                            || "/"        | "/"                            | ""
        "."                            || "me"       | "/home/me"                     | "/home"
        ".."                           || "home"     | "/home"                        | "/"
        "somefile"                     || "somefile" | "somefile"                     | ""
        "dir1/dir2"                    || "dir2"     | "dir1/dir2"                    | "dir1"
        "/home/me/../somedir/somefile" || "somefile" | "/home/me/../somedir/somefile" | "/home/me/../somedir"

    }
}
