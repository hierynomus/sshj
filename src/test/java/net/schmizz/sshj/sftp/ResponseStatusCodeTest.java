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
package net.schmizz.sshj.sftp;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ResponseStatusCodeTest {

    @Test
    public void shouldReturnProperNumericCodesForStatusCode() {
        assertEquals(-1, Response.StatusCode.UNKNOWN.getCode());
        assertEquals(0, Response.StatusCode.OK.getCode());
        assertEquals(1, Response.StatusCode.EOF.getCode());
        assertEquals(2, Response.StatusCode.NO_SUCH_FILE.getCode());
        assertEquals(3, Response.StatusCode.PERMISSION_DENIED.getCode());
        assertEquals(4, Response.StatusCode.FAILURE.getCode());
        assertEquals(5, Response.StatusCode.BAD_MESSAGE.getCode());
        assertEquals(6, Response.StatusCode.NO_CONNECTION.getCode());
        assertEquals(7, Response.StatusCode.CONNECITON_LOST.getCode());
        assertEquals(8, Response.StatusCode.OP_UNSUPPORTED.getCode());
        assertEquals(9, Response.StatusCode.INVALID_HANDLE.getCode());
        assertEquals(10, Response.StatusCode.NO_SUCH_PATH.getCode());
        assertEquals(11, Response.StatusCode.FILE_ALREADY_EXISTS.getCode());
        assertEquals(12, Response.StatusCode.WRITE_PROTECT.getCode());
        assertEquals(13, Response.StatusCode.NO_MEDIA.getCode());
        assertEquals(14, Response.StatusCode.NO_SPACE_ON_FILESYSTEM.getCode());
        assertEquals(15, Response.StatusCode.QUOTA_EXCEEDED.getCode());
        assertEquals(16, Response.StatusCode.UNKNOWN_PRINCIPAL.getCode());
        assertEquals(17, Response.StatusCode.LOCK_CONFLICT.getCode());
        assertEquals(18, Response.StatusCode.DIR_NOT_EMPTY.getCode());
        assertEquals(19, Response.StatusCode.NOT_A_DIRECTORY.getCode());
        assertEquals(20, Response.StatusCode.INVALID_FILENAME.getCode());
        assertEquals(21, Response.StatusCode.LINK_LOOP.getCode());
        assertEquals(22, Response.StatusCode.CANNOT_DELETE.getCode());
        assertEquals(23, Response.StatusCode.INVALID_PARAMETER.getCode());
        assertEquals(24, Response.StatusCode.FILE_IS_A_DIRECTORY.getCode());
        assertEquals(25, Response.StatusCode.BYTE_RANGE_LOCK_CONFLICT.getCode());
        assertEquals(26, Response.StatusCode.BYTE_RANGE_LOCK_REFUSED.getCode());
        assertEquals(27, Response.StatusCode.DELETE_PENDING.getCode());
        assertEquals(28, Response.StatusCode.FILE_CORRUPT.getCode());
        assertEquals(29, Response.StatusCode.OWNER_INVALID.getCode());
        assertEquals(30, Response.StatusCode.GROUP_INVALID.getCode());
        assertEquals(31, Response.StatusCode.NO_MATCHING_BYTE_RANGE_LOCK.getCode());
    }

}
