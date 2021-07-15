package net.schmizz.sshj.examples;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.transport.verification.HostKeyVerifier;
import net.schmizz.sshj.transport.verification.OpenSSHKnownHosts;
import net.schmizz.sshj.xfer.FileSystemFile;

import java.io.*;
import java.nio.charset.Charset;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/** This examples demonstrates how to configure {@link net.schmizz.sshj.SSHClient} client with an in-memory known_hosts file */
public class InMemoryKnownHosts {

    public static void main(String[] args) throws IOException {
        InputStream entry = new ByteArrayInputStream("localhost ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPmhSBtMctNa4hsZt8QGlsYSE5/gMkjeand69Vj4ir13".getBytes(Charset.defaultCharset()));
        SSHClient ssh = new SSHClient();
        ssh.addHostKeyVerifier(new OpenSSHKnownHosts(new InputStreamReader(entry, Charset.defaultCharset())));
        ssh.connect("localhost");
        try {
            ssh.authPublickey(System.getProperty("user.name"));
            ssh.newSCPFileTransfer().download("test_file", new FileSystemFile("/tmp/"));
        } finally {
            ssh.disconnect();
        }
    }

}
