package net.schmizz.sshj.xfer.scp;

import java.io.IOException;

import net.schmizz.sshj.xfer.LocalDestFile;

public interface SCPDownloadClient {

	/**
	 * Download a file from {@code sourcePath} on the connected host to {@code targetPath} locally.
	 */
	int copy(String sourcePath, LocalDestFile targetFile) throws IOException;

	int copy(String sourcePath, LocalDestFile targetFile, ScpCommandLine.EscapeMode escapeMode) throws IOException;

	boolean getRecursiveMode();

	void setRecursiveMode(boolean recursive);
}