package net.schmizz.sshj.xfer;

import java.io.ByteArrayInputStream;
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
}
