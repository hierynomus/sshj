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
        ssh.addHostKeyVerifier(new InMemoryHostKeyVerifier(entry, Charset.defaultCharset()));
        ssh.connect("localhost");
        try {
            ssh.authPublickey(System.getProperty("user.name"));
            ssh.newSCPFileTransfer().download("test_file", new FileSystemFile("/tmp/"));
        } finally {
            ssh.disconnect();
        }
    }

    public static class InMemoryHostKeyVerifier implements HostKeyVerifier {

        private final List<OpenSSHKnownHosts.KnownHostEntry> entries = new ArrayList<OpenSSHKnownHosts.KnownHostEntry>();

        public InMemoryHostKeyVerifier(InputStream inputStream, Charset charset) throws IOException {
            final OpenSSHKnownHosts.EntryFactory entryFactory = new OpenSSHKnownHosts.EntryFactory();
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, charset));
            while(reader.ready()) {
                String line = reader.readLine();
                try {
                    OpenSSHKnownHosts.KnownHostEntry entry = entryFactory.parseEntry(line);
                    if (entry != null) {
                        entries.add(entry);
                    }
                } catch (Exception e) {
                    //log error
                }
            }
        }

        @Override
        public boolean verify(String hostname, int port, PublicKey key) {
            final KeyType type = KeyType.fromKey(key);
            if (type == KeyType.UNKNOWN) {
                return false;
            }

            for (OpenSSHKnownHosts.KnownHostEntry e : entries) {
                try {
                    if (e.appliesTo(type, hostname) && e.verify(key)) {
                        return true;
                    }
                } catch (IOException ioe) {
                    //log error
                }
            }
            return false;
        }
    }

}
