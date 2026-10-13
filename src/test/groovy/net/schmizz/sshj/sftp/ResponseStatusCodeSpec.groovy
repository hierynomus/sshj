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

import spock.lang.Specification
import spock.lang.Unroll

class ResponseStatusCodeSpec extends Specification {

    @Unroll
    def "status #status should have status code #code"() {
        expect:
        code == status.getCode()

        where:
        status                                          || code
        Response.StatusCode.UNKNOWN                     || -1
        Response.StatusCode.OK                          || 0
        Response.StatusCode.EOF                         || 1
        Response.StatusCode.NO_SUCH_FILE                || 2
        Response.StatusCode.PERMISSION_DENIED           || 3
        Response.StatusCode.FAILURE                     || 4
        Response.StatusCode.BAD_MESSAGE                 || 5
        Response.StatusCode.NO_CONNECTION               || 6
        Response.StatusCode.CONNECTION_LOST             || 7
        Response.StatusCode.OP_UNSUPPORTED              || 8
        Response.StatusCode.INVALID_HANDLE              || 9
        Response.StatusCode.NO_SUCH_PATH                || 10
        Response.StatusCode.FILE_ALREADY_EXISTS         || 11
        Response.StatusCode.WRITE_PROTECT               || 12
        Response.StatusCode.NO_MEDIA                    || 13
        Response.StatusCode.NO_SPACE_ON_FILESYSTEM      || 14
        Response.StatusCode.QUOTA_EXCEEDED              || 15
        Response.StatusCode.UNKNOWN_PRINCIPAL           || 16
        Response.StatusCode.LOCK_CONFLICT               || 17
        Response.StatusCode.DIR_NOT_EMPTY               || 18
        Response.StatusCode.NOT_A_DIRECTORY             || 19
        Response.StatusCode.INVALID_FILENAME            || 20
        Response.StatusCode.LINK_LOOP                   || 21
        Response.StatusCode.CANNOT_DELETE               || 22
        Response.StatusCode.INVALID_PARAMETER           || 23
        Response.StatusCode.FILE_IS_A_DIRECTORY         || 24
        Response.StatusCode.BYTE_RANGE_LOCK_CONFLICT    || 25
        Response.StatusCode.BYTE_RANGE_LOCK_REFUSED     || 26
        Response.StatusCode.DELETE_PENDING              || 27
        Response.StatusCode.FILE_CORRUPT                || 28
        Response.StatusCode.OWNER_INVALID               || 29
        Response.StatusCode.GROUP_INVALID               || 30
        Response.StatusCode.NO_MATCHING_BYTE_RANGE_LOCK || 31
    }
}
