/*
 * Copyright 2010-2012 sshj contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.schmizz.sshj;

import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.connection.Connection;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.ConnectionImpl;
import net.schmizz.sshj.connection.channel.direct.LocalPortForwarder;
import net.schmizz.sshj.connection.channel.direct.Session;
import net.schmizz.sshj.connection.channel.direct.SessionChannel;
import net.schmizz.sshj.connection.channel.direct.SessionFactory;
import net.schmizz.sshj.connection.channel.forwarded.ConnectListener;
import net.schmizz.sshj.connection.channel.forwarded.RemotePortForwarder;
import net.schmizz.sshj.connection.channel.forwarded.RemotePortForwarder.ForwardedTCPIPChannel;
import net.schmizz.sshj.connection.channel.forwarded.X11Forwarder;
import net.schmizz.sshj.connection.channel.forwarded.X11Forwarder.X11Channel;
import net.schmizz.sshj.sftp.SFTPClient;
import net.schmizz.sshj.sftp.SFTPEngine;
import net.schmizz.sshj.sftp.StatefulSFTPClient;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.transport.TransportImpl;
import net.schmizz.sshj.transport.compression.DelayedZlibCompression;
import net.schmizz.sshj.transport.compression.NoneCompression;
import net.schmizz.sshj.transport.compression.ZlibCompression;
import net.schmizz.sshj.transport.verification.HostKeyVerifier;
import net.schmizz.sshj.transport.verification.OpenSSHKnownHosts;
import net.schmizz.sshj.userauth.UserAuth;
import net.schmizz.sshj.userauth.UserAuthException;
import net.schmizz.sshj.userauth.UserAuthImpl;
import net.schmizz.sshj.userauth.keyprovider.FileKeyProvider;
import net.schmizz.sshj.userauth.keyprovider.KeyPairWrapper;
import net.schmizz.sshj.userauth.keyprovider.KeyProvider;
import net.schmizz.sshj.userauth.keyprovider.KeyProviderUtil;
import net.schmizz.sshj.userauth.method.AuthKeyboardInteractive;
import net.schmizz.sshj.userauth.method.AuthMethod;
import net.schmizz.sshj.userauth.method.AuthPassword;
import net.schmizz.sshj.userauth.method.AuthPublickey;
import net.schmizz.sshj.userauth.method.PasswordResponseProvider;
import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.PasswordUtils;
import net.schmizz.sshj.userauth.password.Resource;
import net.schmizz.sshj.xfer.scp.SCPFileTransfer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * Secure SHell client API.
 * <p/>
 * Before connection is established, host key verification needs to be accounted for. This is done by {@link
 * #addHostKeyVerifier(HostKeyVerifier) specifying} one or more {@link HostKeyVerifier} objects. Database of known
 * hostname-key pairs in the OpenSSH {@code "known_hosts"} format can be {@link #loadKnownHosts(File) loaded} for host
 * key verification.
 * <p/>
 * User authentication can be performed by any of the {@code auth*()} method.
 * <p/>
 * {@link #startSession()} caters to the most typical use case of starting a {@code session} channel and executing a
 * remote command, starting a subsystem, etc. If you wish to request X11 forwarding for some session, first {@link
 * #registerX11Forwarder(ConnectListener) register} a {@link ConnectListener} for {@code x11} channels.
 * <p/>
 * {@link #newLocalPortForwarder Local} and {@link #getRemotePortForwarder() remote} port forwarding is possible. There
 * are also utility method for easily creating {@link #newSCPFileTransfer SCP} and {@link #newSFTPClient() SFTP}
 * implementations.
 * <p/>
 * <em>A simple example:</em>
 * <p/>
 * <pre>
 * final SSHClient client = new SSHClient();
 * client.loadKnownHosts();
 * client.connect(&quot;hostname&quot;);
 * try {
 *     client.authPassword(&quot;username&quot;, &quot;password&quot;);
 *     final Session session = client.startSession();
 *     try {
 *          final Command cmd = session.exec(&quot;true&quot;);
 *          cmd.join(1, TimeUnit.SECONDS);
 *     } finally {
 *          session.close();
 *     }
 * } finally {
 *      client.disconnect();
 * }
 * </pre>
 * <p/>
 * Where a password or passphrase is required, if you're extra-paranoid use the {@code char[]} based method. The {@code
 * char[]} will be blanked out after use.
 */
public class SSHClient
        extends SocketClient
        implements Closeable, SessionFactory {

    /** Default port for SSH */
    public static final int DEFAULT_PORT = 22;

    /** Logger */
    protected final Logger log = LoggerFactory.getLogger(getClass());

    /** Transport layer */
    protected final Transport trans;

    /** {@code ssh-userauth} service */
    protected final UserAuth auth;

    /** {@code ssh-connection} service */
    protected final Connection conn;

    /** Default constructor. Initializes this object using {@link DefaultConfig}. */
    public SSHClient() {
        this(new DefaultConfig());
    }

    /**
     * Constructor that allows specifying a {@code config} to be used.
     *
     * @param config {@link Config} instance
     */
    public SSHClient(Config config) {
        super(DEFAULT_PORT);
        this.trans = new TransportImpl(config);
        this.auth = new UserAuthImpl(trans);
        this.conn = new ConnectionImpl(trans);
    }

    /**
     * Add a {@link HostKeyVerifier} which will be invoked for verifying host key during connection establishment and
     * future key exchanges.
     *
     * @param hostKeyVerifier {@link HostKeyVerifier} instance
     */
    public void addHostKeyVerifier(HostKeyVerifier hostKeyVerifier) {
        trans.addHostKeyVerifier(hostKeyVerifier);
    }

    /**
     * Add a {@link HostKeyVerifier} that will verify any host that's able to claim a host key with the given {@code
     * fingerprint}, e.g. {@code "4b:69:6c:72:6f:79:20:77:61:73:20:68:65:72:65:21"}
     *
     * @param fingerprint expected fingerprint in colon-delimited format (16 octets in hex delimited by a colon)
     *
     * @see SecurityUtils#getFingerprint
     */
    public void addHostKeyVerifier(final String fingerprint) {
        addHostKeyVerifier(new HostKeyVerifier() {
            @Override
            public boolean verify(String h, int p, PublicKey k) {
                return SecurityUtils.getFingerprint(k).equals(fingerprint);
            }
        });
    }

    /**
     * Authenticate {@code username} using the supplied {@code methods}.
     *
     * @param username user to authenticate
     * @param methods  one or more authentication method
     *
     * @throws UserAuthException  in case of authentication failure
     * @throws TransportException if there was a transport-layer error
     */
    public void auth(String username, AuthMethod... methods)
            throws UserAuthException, TransportException {
        assert isConnected();
        auth(username, Arrays.<AuthMethod>asList(methods));
    }

    /**
     * Authenticate {@code username} using the supplied {@code methods}.
     *
     * @param username user to authenticate
     * @param methods  one or more authentication method
     *
     * @throws UserAuthException  in case of authentication failure
     * @throws TransportException if there was a transport-layer error
     */
    public void auth(String username, Iterable<AuthMethod> methods)
            throws UserAuthException, TransportException {
        assert isConnected();
        auth.authenticate(username, (Service) conn, methods);
    }

    /**
     * Authenticate {@code username} using the {@code "password"} authentication method and as a fallback basic
     * challenge-response authentication.
     *
     * @param username user to authenticate
     * @param password the password to use for authentication
     *
     * @throws UserAuthException  in case of authentication failure
     * @throws TransportException if there was a transport-layer error
     */
    public void authPassword(String username, String password)
            throws UserAuthException, TransportException {
        authPassword(username, password.toCharArray());
    }

    /**
     * Authenticate {@code username} using the {@code "password"} authentication method and as a fallback basic
     * challenge-response authentication.. The {@code password} array is blanked out after use.
     *
     * @param username user to authenticate
     * @param password the password to use for authentication
     *
     * @throws UserAuthException  in case of authentication failure
     * @throws TransportException if there was a transport-layer error
     */
    public void authPassword(final String username, final char[] password)
            throws UserAuthException, TransportException {
        try {
            authPassword(username, new PasswordFinder() {

                @Override
                public char[] reqPassword(Resource<?> resource) {
                    return password.clone();
                }

                @Override
                public boolean shouldRetry(Resource<?> resource) {
                    return false;
                }

            });
        } finally {
            PasswordUtils.blankOut(password);
        }
    }

    /**
     * Authenticate {@code username} using the {@code "password"} authentication method and as a fallback basic
     * challenge-response authentication.
     *
     * @param username user to authenticate
     * @param pfinder  the {@link PasswordFinder} to use for authentication
     *
     * @throws UserAuthException  in case of authentication failure
     * @throws TransportException if there was a transport-layer error
     */
    public void authPassword(String username, PasswordFinder pfinder)
            throws UserAuthException, TransportException {
        auth(username, new AuthPassword(pfinder), new AuthKeyboardInteractive(new PasswordResponseProvider(pfinder)));
    }

    /**
     * Authenticate {@code username} using the {@code "publickey"} authentication method, with keys from some common
     * locations on the file system. This method relies on {@code ~/.ssh/id_rsa} and {@code ~/.ssh/id_dsa}.
     * <p/>
     * This method does not provide a way to specify a passphrase.
     *
     * @param username user to authenticate
     *
     * @throws UserAuthException  in case of authentication failure
     * @throws TransportException if there was a transport-layer error
     */
    public void authPublickey(String username)
            throws UserAuthException, TransportException {
        final String base = System.getProperty("user.home") + File.separator + ".ssh" + File.separator;
        authPublickey(username, base + "id_rsa", base + "id_dsa");
    }

    /**
     * Authenticate {@code username} using the {@code "publickey"} authentication method.
     * <p/>
     * {@link KeyProvider} instances can be created using any of the of the {@code loadKeys()} method provided in this
     * class. In case multiple {@code keyProviders} are specified; authentication is attempted in order as long as the
     * {@code "publickey"} authentication method is available.
     *
     * @param username     user to authenticate
     * @param keyProviders one or more {@link KeyProvider} instances
     *
     * @throws UserAuthException  in case of authentication failure
     * @throws TransportException if there was a transport-layer error
     */
    public void authPublickey(String username, Iterable<KeyProvider> keyProviders)
            throws UserAuthException,
                   TransportException {
        final List<AuthMethod> am = new LinkedList<AuthMethod>();
        for (KeyProvider kp : keyProviders)
            am.add(new AuthPublickey(kp));
        auth(username, am);
    }

    /**
     * Authenticate {@code username} using the {@code "publickey"} authentication method.
     * <p/>
     * {@link KeyProvider} instances can be created using any of the {@code loadKeys()} method provided in this class.
     * In case multiple {@code keyProviders} are specified; authentication is attempted in order as long as the {@code
     * "publickey"} authentication method is available.
     *
     * @param username     user to authenticate
     * @param keyProviders one or more {@link KeyProvider} instances
     *
     * @throws UserAuthException  in case of authentication failure
     * @throws TransportException if there was a transport-layer error
     */
    public void authPublickey(String username, KeyProvider... keyProviders)
            throws UserAuthException,
                   TransportException {
        authPublickey(username, Arrays.<KeyProvider>asList(keyProviders));
    }

    /**
     * Authenticate {@code username} using the {@code "publickey"} authentication method, with keys from one or more
     * {@code locations} in the file system.
     * <p/>
     * In case multiple {@code locations} are specified; authentication is attempted in order as long as the {@code
     * "publickey"} authentication method is available. If there is an error loading keys from any of them (e.g. file
     * could not be read, file format not recognized) that key file it is ignored.
     * <p/>
     * This method does not provide a way to specify a passphrase.
     *
     * @param username  user to authenticate
     * @param locations one or more locations in the file system containing the private key
     *
     * @throws UserAuthException  in case of authentication failure
     * @throws TransportException if there was a transport-layer error
     */
    public void authPublickey(String username, String... locations)
            throws UserAuthException, TransportException {
        final List<KeyProvider> keyProviders = new LinkedList<KeyProvider>();
        for (String loc : locations)
            try {
                log.debug("Attempting to load key from: {}", loc);
                keyProviders.add(loadKeys(loc));
            } catch (IOException logged) {
                log.warn("Could not load keys due to: {}", logged);
            }
        authPublickey(username, keyProviders);
    }

    /**
     * Disconnects from the connected SSH server. {@code SSHClient} objects are not reusable therefore it is incorrect
     * to attempt connection after this method has been called.
     * <p/>
     * This method should be called from a {@code finally} construct after connection is established; so that proper
     * cleanup is done and the thread spawned by the transport layer for dealing with incoming packets is stopped.
     */
    @Override
    public void disconnect()
            throws IOException {
        trans.disconnect();
        super.disconnect();
        assert !isConnected();
    }

    /** @return the associated {@link Connection} instance. */
    public Connection getConnection() {
        return conn;
    }

    /** @return a {@link RemotePortForwarder} that allows requesting remote forwarding over this connection. */
    public RemotePortForwarder getRemotePortForwarder() {
        synchronized (conn) {
            RemotePortForwarder rpf = (RemotePortForwarder) conn.get(ForwardedTCPIPChannel.TYPE);
            if (rpf == null)
                conn.attach(rpf = new RemotePortForwarder(conn));
            return rpf;
        }
    }

    /** @return the associated {@link Transport} instance. */
    public Transport getTransport() {
        return trans;
    }

    /**
     * @return the associated {@link UserAuth} instance. This allows access to information like the {@link
     *         UserAuth#getBanner() authentication banner}, whether authentication was at least {@link
     *         UserAuth#hadPartialSuccess() partially successful}, and any {@link UserAuth#getSavedExceptions() saved
     *         exceptions} that were ignored because there were more authentication method that could be tried.
     */
    public UserAuth getUserAuth() {
        return auth;
    }

    /** @return whether authenticated. */
    public boolean isAuthenticated() {
        return trans.isAuthenticated();
    }

    /** @return whether connected. */
    @Override
    public boolean isConnected() {
        return super.isConnected() && trans.isRunning();
    }

    /**
     * Creates a {@link KeyProvider} from supplied {@link KeyPair}.
     *
     * @param kp the key pair
     *
     * @return the key provider ready for use in authentication
     */
    public KeyProvider loadKeys(KeyPair kp) {
        return new KeyPairWrapper(kp);
    }

    /**
     * Returns a {@link KeyProvider} instance created from a location on the file system where an <em>unencrypted</em>
     * private key file (does not require a passphrase) can be found. Simply calls {@link #loadKeys(String,
     * PasswordFinder)} with the {@link PasswordFinder} argument as {@code null}.
     *
     * @param location the location for the key file
     *
     * @return the key provider ready for use in authentication
     *
     * @throws SSHException if there was no suitable key provider available for the file format; typically because
     *                      BouncyCastle is not in the classpath
     * @throws IOException  if the key file format is not known, if the file could not be read, etc.
     */
    public KeyProvider loadKeys(String location)
            throws IOException {
        return loadKeys(location, (PasswordFinder) null);
    }

    /**
     * Utility function for createing a {@link KeyProvider} instance from given location on the file system. Creates a
     * one-off {@link PasswordFinder} using {@link PasswordUtils#createOneOff(char[])}, and calls {@link
     * #loadKeys(String, PasswordFinder)}.
     *
     * @param location   location of the key file
     * @param passphrase passphrase as a char-array
     *
     * @return the key provider ready for use in authentication
     *
     * @throws SSHException if there was no suitable key provider available for the file format; typically because
     *                      BouncyCastle is not in the classpath
     * @throws IOException  if the key file format is not known, if the file could not be read, etc.
     */
    public KeyProvider loadKeys(String location, char[] passphrase)
            throws IOException {
        return loadKeys(location, PasswordUtils.createOneOff(passphrase));
    }

    /**
     * Creates a {@link KeyProvider} instance from given location on the file system. Currently only PKCS8 format
     * private key files are supported (OpenSSH uses this format).
     * <p/>
     *
     * @param location       the location of the key file
     * @param passwordFinder the {@link PasswordFinder} that can supply the passphrase for decryption (may be {@code
     *                       null} in case keyfile is not encrypted)
     *
     * @return the key provider ready for use in authentication
     *
     * @throws SSHException if there was no suitable key provider available for the file format; typically because
     *                      BouncyCastle is not in the classpath
     * @throws IOException  if the key file format is not known, if the file could not be read, etc.
     */
    public KeyProvider loadKeys(String location, PasswordFinder passwordFinder)
            throws IOException {
        final File loc = new File(location);
        final FileKeyProvider.Format format = KeyProviderUtil.detectKeyFileFormat(loc);
        final FileKeyProvider fkp =
                Factory.Named.Util.create(trans.getConfig().getFileKeyProviderFactories(), format.toString());
        if (fkp == null)
            throw new SSHException("No provider available for " + format + " key file");
        fkp.init(loc, passwordFinder);
        return fkp;
    }

    /**
     * Convenience method for creating a {@link KeyProvider} instance from a {@code location} where an <i>encrypted</i>
     * key file is located. Calls {@link #loadKeys(String, char[])} with a character array created from the supplied
     * {@code passphrase} string.
     *
     * @param location   location of the key file
     * @param passphrase passphrase as a string
     *
     * @return the key provider for use in authentication
     *
     * @throws IOException if the key file format is not known, if the file could not be read etc.
     */
    public KeyProvider loadKeys(String location, String passphrase)
            throws IOException {
        return loadKeys(location, passphrase.toCharArray());
    }

    /**
     * Creates a {@link KeyProvider} instance from passed strings. Currently only PKCS8 format private key files are
     * supported (OpenSSH uses this format).
     * <p/>
     *
     * @param privateKey     the private key as a string
     * @param publicKey      the public key as a string if it's not included with the private key
     * @param passwordFinder the {@link PasswordFinder} that can supply the passphrase for decryption (may be {@code
     *                       null} in case keyfile is not encrypted)
     *
     * @return the key provider ready for use in authentication
     *
     * @throws SSHException if there was no suitable key provider available for the file format; typically because
     *                      BouncyCastle is not in the classpath
     * @throws IOException  if the key file format is not known, etc.
     */
    public KeyProvider loadKeys(String privateKey, String publicKey, PasswordFinder passwordFinder)
            throws IOException {
        final FileKeyProvider.Format format = KeyProviderUtil.detectKeyFileFormat(privateKey, publicKey != null);
        final FileKeyProvider fkp =
                Factory.Named.Util.create(trans.getConfig().getFileKeyProviderFactories(), format.toString());
        if (fkp == null)
            throw new SSHException("No provider available for " + format + " key file");
        fkp.init(privateKey, publicKey, passwordFinder);
        return fkp;
    }

    /**
     * Attempts loading the user's {@code known_hosts} file from the default locations, i.e. {@code ~/.ssh/known_hosts}
     * and {@code ~/.ssh/known_hosts2} on most platforms. Adds the resulting {@link OpenSSHKnownHosts} object as a host
     * key verifier.
     * <p/>
     * For finer control over which file is used, see {@link #loadKnownHosts(File)}.
     *
     * @throws IOException if there is an error loading from <em>both</em> locations
     */
    public void loadKnownHosts()
            throws IOException {
        boolean loaded = false;
        final File sshDir = OpenSSHKnownHosts.detectSSHDir();
        if (sshDir != null) {
            for (File loc : Arrays.asList(new File(sshDir, "known_hosts"), new File(sshDir, "known_hosts2"))) {
                try {
                    loadKnownHosts(loc);
                    loaded = true;
                } catch (IOException e) {
                    // Ignore for now
                }
            }
        }
        if (!loaded)
            throw new IOException("Could not load known_hosts");
    }

    /**
     * Adds a {@link OpenSSHKnownHosts} object created from the specified location as a host key verifier.
     *
     * @param location location for {@code known_hosts} file
     *
     * @throws IOException if there is an error loading from any of these locations
     */
    public void loadKnownHosts(File location)
            throws IOException {
        addHostKeyVerifier(new OpenSSHKnownHosts(location));
    }

    /**
     * Create a {@link LocalPortForwarder} that will listen based on {@code parameters} using the bound
     * {@code serverSocket} and forward incoming connections to the server; which will further forward them to
     * {@code host:port}.
     * <p/>
     * The returned forwarder's {@link LocalPortForwarder#listen() listen()} method should be called to actually start
     * listening, this method just creates an instance.
     *
     * @param parameters   parameters for the forwarding setup
     * @param serverSocket bound server socket
     *
     * @return a {@link LocalPortForwarder}
     */
    public LocalPortForwarder newLocalPortForwarder(LocalPortForwarder.Parameters parameters,
                                                    ServerSocket serverSocket) {
        return new LocalPortForwarder(conn, parameters, serverSocket);
    }

    /**
     * Register a {@code listener} for handling forwarded X11 channels. Without having done this, an incoming X11
     * forwarding will be summarily rejected.
     * <p/>
     * It should be clarified that multiple listeners for X11 forwarding over a single SSH connection are not supported
     * (and don't make much sense). So a subsequent call to this method is only going to replace the registered {@code
     * listener}.
     *
     * @param listener the {@link ConnectListener} that should be delegated the responsibility of handling forwarded
     *                 {@link X11Channel} 's
     *
     * @return an {@link X11Forwarder} that allows to {@link X11Forwarder#stop() stop acting} on X11 requests from
     *         server
     */
    public X11Forwarder registerX11Forwarder(ConnectListener listener) {
        final X11Forwarder x11f = new X11Forwarder(conn, listener);
        conn.attach(x11f);
        return x11f;
    }

    /** @return Instantiated {@link SCPFileTransfer} implementation. */
    public SCPFileTransfer newSCPFileTransfer() {
        assert isConnected() && isAuthenticated();
        return new SCPFileTransfer(this);
    }

    /**
     * @return Instantiated {@link SFTPClient} implementation.
     *
     * @throws IOException if there is an error starting the {@code sftp} subsystem
     * @see StatefulSFTPClient
     */
    public SFTPClient newSFTPClient()
            throws IOException {
        assert isConnected() && isAuthenticated();
        return new SFTPClient(new SFTPEngine(this).init());
    }

    /**
     * Does key re-exchange.
     *
     * @throws TransportException if an error occurs during key exchange
     */
    public void rekey()
            throws TransportException {
        doKex();
    }

    @Override
    public Session startSession()
            throws ConnectionException, TransportException {
        assert isConnected() && isAuthenticated();
        final SessionChannel sess = new SessionChannel(conn);
        sess.open();
        assert sess.isOpen();
        return sess;
    }

    /**
     * Adds {@code zlib} compression to preferred compression algorithms. There is no guarantee that it will be
     * successfully negotiatied.
     * <p/>
     * If the client is already connected renegotiation is done; otherwise this method simply returns (and compression
     * will be negotiated during connection establishment).
     *
     * @throws ClassNotFoundException if {@code JZlib} is not in classpath
     * @throws TransportException     if an error occurs during renegotiation
     */
    public void useCompression()
            throws TransportException {
        trans.getConfig().setCompressionFactories(Arrays.asList(
                new DelayedZlibCompression.Factory(),
                new ZlibCompression.Factory(),
                new NoneCompression.Factory()));
        if (isConnected())
            rekey();
    }

    /** On connection establishment, also initializes the SSH transport via {@link Transport#init} and {@link #doKex()}. */
    @Override
    protected void onConnect()
            throws IOException {
        super.onConnect();
        trans.init(getRemoteHostname(), getRemotePort(), getInputStream(), getOutputStream());
        doKex();
    }

    /**
     * Do key exchange.
     *
     * @throws TransportException if error during kex
     */
    protected void doKex()
            throws TransportException {
        assert trans.isRunning();

        final long start = System.currentTimeMillis();
        trans.doKex();
        log.info("Key exchange took {} seconds", (System.currentTimeMillis() - start) / 1000.0);
    }

    /**
     * Same as {@link #disconnect()}.
     *
     * @throws IOException
     */
    @Override
    public void close()
            throws IOException {
        disconnect();
    }

}