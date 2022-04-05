/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package net.schmizz.sshj.sftp;

import com.hierynomus.sshj.test.SshFixture;
import com.hierynomus.sshj.test.util.FileUtil;
import java.io.File;
import java.io.IOException;
import net.schmizz.sshj.SSHClient;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 *
 * @author Brent Tyler
 */
public class SFTPFileTransferTest {
    
    public static final String TARGET_FILE_NAME = "target.txt";
    
    File targetDir;
    File targetFile;
    File sourceFile;
    
    File partialFile;
    
    SSHClient sshClient;
    SFTPFileTransfer xfer;
    
    @Rule
    public SshFixture fixture = new SshFixture();

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    @Before
    public void init() throws IOException {
        targetDir   = tempFolder.newFolder();
        targetFile  = new File(targetDir, TARGET_FILE_NAME);
        sourceFile  = new File("src/test/resources/files/test_file_full.txt");
        
        partialFile = new File("src/test/resources/files/test_file_partial.txt");
        
        sshClient   = fixture.setupConnectedDefaultClient();
        sshClient.authPassword("test", "test");
        xfer = sshClient.newSFTPClient().getFileTransfer();
    }
    
    @After
    public void cleanup() {
        if (targetFile.exists()) {
            targetFile.delete();
        }
        
        if (targetDir.exists()) {
            targetDir.delete();
        }
    }
    
    private void performDownload(boolean resume) throws IOException {
        // Using the resume param this way to call the different entry points into the FileTransfer interface
        if (resume) {
            xfer.download(sourceFile.getAbsolutePath(), targetFile.getAbsolutePath(), true);
        } else {
            xfer.download(sourceFile.getAbsolutePath(), targetFile.getAbsolutePath());
        }
        
        assertTrue(FileUtil.compareFileContents(sourceFile, targetFile));
    }
    
    private void performUpload(boolean resume) throws IOException {
        // Using the resume param this way to call the different entry points into the FileTransfer interface
        if (resume) {
            xfer.upload(sourceFile.getAbsolutePath(), targetFile.getAbsolutePath(), true);
        } else {
            xfer.upload(sourceFile.getAbsolutePath(), targetFile.getAbsolutePath());
        }
        assertTrue(FileUtil.compareFileContents(sourceFile, targetFile));
    }
    
    @Test
    public void testDownload() throws IOException {
        performDownload(false);
    }
    
    @Test
    public void testDownloadResumePartial() throws IOException {
        FileUtil.writeToFile(targetFile, FileUtil.readFromFile(partialFile));
        assertFalse(FileUtil.compareFileContents(sourceFile, targetFile));
        performDownload(true);
    }
    
    @Test
    public void testDownloadResumeNothing() throws IOException {
        assertFalse(targetFile.exists());
        performDownload(true);
    }
    
    @Test
    public void testDownloadResumePreviouslyCompleted() throws IOException {
        FileUtil.writeToFile(targetFile, FileUtil.readFromFile(sourceFile));
        assertTrue(FileUtil.compareFileContents(sourceFile, targetFile));
        performDownload(true);
    }
    
    @Test
    public void testUpload() throws IOException {
        performUpload(false);
    }
    
    @Test
    public void testUploadResumePartial() throws IOException {
        FileUtil.writeToFile(targetFile, FileUtil.readFromFile(partialFile));
        assertFalse(FileUtil.compareFileContents(sourceFile, targetFile));
        performUpload(true);
    }
    
    @Test
    public void testUploadResumeNothing() throws IOException {
        assertFalse(targetFile.exists());
        performUpload(true);
    }
    
    @Test
    public void testUploadResumePreviouslyCompleted() throws IOException {
        FileUtil.writeToFile(targetFile, FileUtil.readFromFile(sourceFile));
        assertTrue(FileUtil.compareFileContents(sourceFile, targetFile));
        performUpload(true);
    }
}
