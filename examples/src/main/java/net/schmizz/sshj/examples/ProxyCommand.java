package net.schmizz.sshj.examples;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.TimeUnit;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.connection.channel.direct.Session;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;

/**
 * This example uses a separate process to handle I/O, similar to the "ProxyCommand" directive in openssh.
 */
public class ProxyCommand {
    public static void main(String... args)
            throws IOException {
    	
    	/* 
    	for testing, uses a locally-installed ssh client,
    	
    	but for AWS SSM, once you've negotiated the OAuth/SAML login for SSO, 
    	then called StsClient.getCallerIdentity() to check that worked
    	then called Ec2Client.describeInstances() to convert an IP to an instanceId/availableZone combo
    	then called Ec2InstanceConnectClient.sendSSHPublicKey() to open a 60-second login window 
    	you'd create an SSM ssh session via something like
    	 
    	ProcessBuilder pb = new ProcessBuilder("aws", "ssm", "start-session", "--region", "ap-southeast-2", "--target", instanceId,
	       "--document-name", "AWS-StartSSHSession",
	       "--parameters", "portNumber=22"
	    
	    and wire up the inputStreams/outputStreams from that instead.
    	*/
    	
    	
    	// for testing only
    	String jumpBox = "localhost";   // this would typically be something remote
    	String targetBox = "localhost"; // this would typically be something even more remote    	
    	ProcessBuilder pb = new ProcessBuilder("ssh", jumpBox, "-W", targetBox + ":22");
    	Process proc = pb.start();
    	InputStream recvStream = proc.getInputStream();
    	OutputStream xmitStream = proc.getOutputStream();
    	
        SSHClient ssh = new SSHClient();
        ssh.addHostKeyVerifier(new PromiscuousVerifier());
        ssh.connectVia(recvStream, xmitStream);
        
        try {
            ssh.authPublickey(System.getProperty("user.name"));
            final Session session = ssh.startSession();
            try {
                final Session.Command cmd = session.exec("ping -c 1 google.com");
                System.out.println(IOUtils.readFully(cmd.getInputStream()).toString());
                cmd.join(5, TimeUnit.SECONDS);
                System.out.println("\n** exit status: " + cmd.getExitStatus());
            } finally {
                session.close();
            }
        } finally {
        	ssh.disconnect();
        	ssh.close();
        }
    }
}
