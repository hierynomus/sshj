/*
 * Copyright 2010, 2011 sshj contributors
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
package net.schmizz.sshj.xfer;

import java.io.ByteArrayInputStream;
import java.io.FileFilter;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;

public class InMemoryFile implements LocalFile {

	private static final int EOF = -1;
	private static final int DEFAULT_BUFFER_SIZE = 4096;
	
	private String name;
	private Long cachedLength;
	private InputStream stream;

	public InMemoryFile(String filename, ByteArrayInputStream stream) {
		this.name = filename;
		this.stream = stream;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public boolean isDirectory() {
		return false;
	}

	@Override
	public boolean isFile() {
		return true;
	}

	@Override
	public long length() {
		if (cachedLength == null) {
			cachedLength = computeLength(); 
		}
		return cachedLength;
	}

	private long computeLength() {
		try {
			byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
			long length = 0;
			int readBytes = 0;
			while (EOF != (readBytes = stream.read(buffer))) {
				length += readBytes;
			}
			stream.reset();
			return length;
		} catch (IOException e) {
			throw new RuntimeException("Impossible to read in memory file", e);
		}
	}

	@Override
	public long lastModified() {
		return System.currentTimeMillis() / 1000;
	}

	@Override
	public InputStream stream() {
		return stream;
	}

	@Override
	public Iterable<LocalFile> getChildren() {
		return Collections.emptyList();
	}

	@Override
	public Iterable<LocalFile> getChildren(FileFilter filter)
			throws IOException {
		return Collections.emptyList();
	}

}
