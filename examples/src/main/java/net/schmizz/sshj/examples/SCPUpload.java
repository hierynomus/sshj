package net.schmizz.sshj.examples;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.xfer.FileSystemFile;

import java.io.File;
import java.io.IOException;

/** This example demonstrates uploading of a file over SCP to the SSH server. */
public class SCPUpload {

    public static void main(String[] args)
            throws IOException, ClassNotFoundException {
        SSHClient ssh = new SSHClient();
        ssh.loadKnownHosts();
        ssh.connect("localhost");
        try {
            ssh.authPublickey(System.getProperty("user.name"));

            // Present here to demo algorithm renegotiation - could have just put this before connect()
            // Make sure JZlib is in classpath for this to work
            ssh.useCompression();

            final String src = System.getProperty("user.home") + File.separator + "test_file";
            ssh.newSCPFileTransfer().upload(new FileSystemFile(src), "/tmp/");
        } finally {
            ssh.disconnect();
        }
    }
}
