package net.schmizz.sshj.examples;

import com.hierynomus.sshj.userauth.agent.AgentProxy;
import com.hierynomus.sshj.userauth.agent.AuthAgent;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.connection.channel.direct.Session;

import java.io.IOException;

/**
 * Authenticates with a FIDO/U2F security key (e.g. a YubiKey holding an {@code ed25519-sk} or
 * {@code ecdsa-sk} key) by delegating to the system SSH agent.
 * <p>
 * Load the key into your agent once, then run this:
 * <pre>
 *   ssh-add ~/.ssh/id_ed25519_sk     # tap the key once to register it with the agent
 *   ./run SecurityKeyAgentAuth
 * </pre>
 * The agent performs the hardware tap on every authentication, so sshj never has to talk to the
 * authenticator directly. This also works for ordinary RSA/ECDSA/Ed25519 keys held by the agent.
 */
public class SecurityKeyAgentAuth {

    public static void main(String... args) throws IOException {
        final SSHClient ssh = new SSHClient();
        ssh.loadKnownHosts();
        ssh.connect("localhost");
        // AgentProxy.fromEnvironment() connects to $SSH_AUTH_SOCK (requires a Java 16+ runtime for
        // unix-domain sockets; supply your own AgentConnection on older JVMs or other platforms).
        try (AgentProxy agent = AgentProxy.fromEnvironment()) {
            ssh.auth(System.getProperty("user.name"), AuthAgent.fromIdentities(agent));
            final Session session = ssh.startSession();
            try {
                session.exec("echo authenticated with a security key").join();
            } finally {
                session.close();
            }
        } finally {
            ssh.disconnect();
        }
    }
}
