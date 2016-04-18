package net.schmizz.sshj.examples;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.xfer.FileSystemFile;

import java.io.IOException;

/** This example demonstrates downloading of a file over SCP from the SSH server. */
public class SCPDownload {

    public static void main(String[] args)
            throws IOException {
        SSHClient ssh = new SSHClient();
        // ssh.useCompression(); // Can lead to significant speedup (needs JZlib in classpath)
        ssh.loadKnownHosts();
        ssh.connect("localhost");
        try {
            ssh.authPublickey(System.getProperty("user.name"));
            ssh.newSCPFileTransfer().download("test_file", new FileSystemFile("/tmp/"));
        } finally {
            ssh.disconnect();
        }
    }

}
