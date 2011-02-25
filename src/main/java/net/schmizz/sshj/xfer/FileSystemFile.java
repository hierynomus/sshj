package net.schmizz.sshj.xfer;

import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;


public class FileSystemFile implements LocalFile {

	private File file;
	private FileFilter fileFilter;

	public FileSystemFile(String path) {
		this.file = new File(path);
	}
	
	public void setFileFilter(FileFilter fileFilter) {
		this.fileFilter = fileFilter;
	}

	@Override
	public String getName() {
		return file.getName();
	}

	@Override
	public boolean isDirectory() {
		return file.isDirectory();
	}

	@Override
	public boolean isFile() {
		return file.isFile();
	}

	@Override
	public long length() {
		return file.length();
	}

	@Override
	public long lastModified() {
		return file.lastModified();
	}

	@Override
	public InputStream stream() throws IOException {
		return new FileInputStream(file);
	}

	@Override
	public Iterable<LocalFile> getChildren() throws IOException {
		return getChildren(file);
	}

	private Iterable<LocalFile> getChildren(File f) throws IOException {
		Collection<LocalFile> files = new ArrayList<LocalFile>();
		File[] childFiles = fileFilter == null ? f.listFiles() : f.listFiles(fileFilter);
		if (childFiles == null)
			throw new IOException("Error listing files in directory: " + f);
		
		for (File childFile : childFiles) {
			FileSystemFile localChild = new FileSystemFile(childFile.getName());
			localChild.setFileFilter(fileFilter);
			files.add(localChild);
		}
		return files;
	}
}
