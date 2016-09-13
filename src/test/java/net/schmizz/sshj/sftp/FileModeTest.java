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

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

public class FileModeTest {

    @Test
    public void shouldDetectDirectoryWithLinuxMask() {
        FileMode fileMode = new FileMode(040755);
        assertThat(fileMode.toString(), equalTo("[mask=40755]"));
        assertThat(fileMode.getType(), equalTo(FileMode.Type.DIRECTORY));
    }

    @Test
    public void shouldDetectDirectoryWithAixUnixMask() {
        FileMode fileMode = new FileMode(0240755);
        assertThat(fileMode.toString(), equalTo("[mask=240755]"));
        assertThat(fileMode.getType(), equalTo(FileMode.Type.DIRECTORY));
    }
}
