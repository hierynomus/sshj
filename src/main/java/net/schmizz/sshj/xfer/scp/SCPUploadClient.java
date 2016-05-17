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
package net.schmizz.sshj.xfer.scp;

import java.io.IOException;

import net.schmizz.sshj.xfer.LocalFileFilter;
import net.schmizz.sshj.xfer.LocalSourceFile;

/** Support for uploading files over a connected link using SCP. */
public interface SCPUploadClient {

	/** Upload a local file from {@code localFile} to {@code targetPath} on the remote host. */
	int copy(LocalSourceFile sourceFile, String remotePath) throws IOException;

	int copy(LocalSourceFile sourceFile, String remotePath, ScpCommandLine.EscapeMode escapeMode) throws IOException;

	void setUploadFilter(LocalFileFilter uploadFilter);
}