package net.schmizz.sshj.xfer;

import java.io.IOException;
import java.io.InputStream;

public interface LocalFile {
	String getName();

	boolean isDirectory();
	boolean isFile();

	long length();

	long lastModified();
	
	InputStream stream() throws IOException;

	Iterable<LocalFile> getChildren() throws IOException;
}
