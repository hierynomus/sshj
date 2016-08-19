/*
 * Copyright (C)2009 - SSHJ Contributors
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
package net.schmizz.sshj.userauth.method;

import net.schmizz.sshj.common.Buffer.BufferException;
import net.schmizz.sshj.common.Buffer.PlainBuffer;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.userauth.UserAuthException;
import org.ietf.jgss.*;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.List;

/** Implements authentication by GSS-API. */
public class AuthGssApiWithMic
        extends AbstractAuthMethod {

    private final LoginContext loginContext;
    private final List<Oid> mechanismOids;
    private final GSSManager manager;

    private GSSContext secContext;

    public AuthGssApiWithMic(LoginContext loginContext, List<Oid> mechanismOids) {
        this(loginContext, mechanismOids, GSSManager.getInstance());
    }

    public AuthGssApiWithMic(LoginContext loginContext, List<Oid> mechanismOids, GSSManager manager) {
        super("gssapi-with-mic");
        this.loginContext = loginContext;
        this.mechanismOids = mechanismOids;
        this.manager = manager;

        secContext = null;
    }

    @Override
    public SSHPacket buildReq()
            throws UserAuthException {
        SSHPacket packet = super.buildReq() // the generic stuff
                .putUInt32(mechanismOids.size()); // number of OIDs we support
        for (Oid oid : mechanismOids) {
            try {
                packet.putString(oid.getDER());
            } catch (GSSException e) {
                throw new UserAuthException("Mechanism OID could not be encoded: " + oid.toString(), e);
            }
        }

        return packet;
    }

    /**
     * PrivilegedExceptionAction to be executed within the given LoginContext for
     * initializing the GSSContext.
     *
     * @author Ben Hamme
     */
    private class InitializeContextAction implements PrivilegedExceptionAction<GSSContext> {

        private final Oid selectedOid;

        public InitializeContextAction(Oid selectedOid) {
            this.selectedOid = selectedOid;
        }

        @Override
        public GSSContext run() throws GSSException {
            GSSName clientName = manager.createName(params.getUsername(), GSSName.NT_USER_NAME);
            GSSCredential clientCreds = manager.createCredential(clientName, GSSContext.DEFAULT_LIFETIME, selectedOid, GSSCredential.INITIATE_ONLY);
            GSSName peerName = manager.createName("host@" + params.getTransport().getRemoteHost(), GSSName.NT_HOSTBASED_SERVICE);

            GSSContext context = manager.createContext(peerName, selectedOid, clientCreds, GSSContext.DEFAULT_LIFETIME);
            context.requestMutualAuth(true);
            context.requestInteg(true);

            return context;
        }
    }

    private void sendToken(byte[] token) throws TransportException {
        SSHPacket packet = new SSHPacket(Message.USERAUTH_INFO_RESPONSE).putString(token);
        params.getTransport().write(packet);
    }

    private void handleContextInitialization(SSHPacket buf)
            throws UserAuthException, TransportException {
        byte[] bytes;
        try {
            bytes = buf.readBytes();
        } catch (BufferException e) {
            throw new UserAuthException("Failed to read byte array from message buffer", e);
        }

        Oid selectedOid;
        try {
            selectedOid = new Oid(bytes);
        } catch (GSSException e) {
            throw new UserAuthException("Exception constructing OID from server response", e);
        }

        log.debug("Server selected OID: {}", selectedOid.toString());
        log.debug("Initializing GSSAPI context");

        Subject subject = loginContext.getSubject();

        try {
            secContext = Subject.doAs(subject, new InitializeContextAction(selectedOid));
        } catch (PrivilegedActionException e) {
            throw new UserAuthException("Exception during context initialization", e);
        }

        log.debug("Sending initial token");
        byte[] inToken = new byte[0];
        try {
            byte[] outToken = secContext.initSecContext(inToken, 0, inToken.length);
            sendToken(outToken);
        } catch (GSSException e) {
            throw new UserAuthException("Exception sending initial token", e);
        }
    }

    private byte[] handleTokenFromServer(SSHPacket buf) throws UserAuthException {
        byte[] token;

        try {
            token = buf.readStringAsBytes();
        } catch (BufferException e) {
            throw new UserAuthException("Failed to read string from message buffer", e);
        }

        try {
            return secContext.initSecContext(token, 0, token.length);
        } catch (GSSException e) {
            throw new UserAuthException("Exception during token exchange", e);
        }
    }

    private byte[] generateMIC() throws UserAuthException {
        byte[] msg = new PlainBuffer().putString(params.getTransport().getSessionID())
                            .putByte(Message.USERAUTH_REQUEST.toByte())
                            .putString(params.getUsername())
                            .putString(params.getNextServiceName())
                            .putString(getName())
                            .getCompactData();

        try {
            return secContext.getMIC(msg, 0, msg.length, null);
        } catch (GSSException e) {
            throw new UserAuthException("Exception getting message integrity code", e);
        }
    }

    @Override
    public void handle(Message cmd, SSHPacket buf)
            throws UserAuthException, TransportException {
        if (cmd == Message.USERAUTH_60) {
            handleContextInitialization(buf);
        } else if (cmd == Message.USERAUTH_INFO_RESPONSE) {
            byte[] token = handleTokenFromServer(buf);

            if (!secContext.isEstablished()) {
                log.debug("Sending token");
                sendToken(token);
            } else {
                if (secContext.getIntegState()) {
                    log.debug("Per-message integrity protection available: finalizing authentication with message integrity code");
                    params.getTransport().write(new SSHPacket(Message.USERAUTH_GSSAPI_MIC).putString(generateMIC()));
                } else {
                    log.debug("Per-message integrity protection unavailable: finalizing authentication");
                    params.getTransport().write(new SSHPacket(Message.USERAUTH_GSSAPI_EXCHANGE_COMPLETE));
                }
            }
        } else {
            super.handle(cmd, buf);
        }
    }
}
