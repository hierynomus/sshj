package net.schmizz.sshj.xfer.scp;

import java.io.IOException;

import net.schmizz.sshj.xfer.LocalFileFilter;
import net.schmizz.sshj.xfer.LocalSourceFile;

public interface SCPUploadClient {

	/**
	 * Upload a local file from {@code localFile} to {@code targetPath} on the remote host.
	 */
	int copy(LocalSourceFile sourceFile, String remotePath) throws IOException;

	int copy(LocalSourceFile sourceFile, String remotePath, ScpCommandLine.EscapeMode escapeMode) throws IOException;

	void setUploadFilter(LocalFileFilter uploadFilter);
}