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
package net.schmizz.sshj.util.gss;

import org.ietf.jgss.*;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static net.schmizz.sshj.util.gss.BogusGSSManager.unavailable;

public class BogusGSSContext
        implements GSSContext {

    private static final byte[] INIT_TOKEN = fromString("INIT");
    private static final byte[] ACCEPT_TOKEN = fromString("ACCEPT");
    private static final byte[] MIC = fromString("LGTM");

    private static byte[] fromString(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private boolean initialized = false;
    private boolean accepted = false;
    private boolean integState = false;
    private boolean mutualAuthState = false;

    @Override
    public byte[] initSecContext(byte[] inputBuf, int offset, int len) throws GSSException {
        initialized = true;
        return INIT_TOKEN;
    }

    @Override
    public int initSecContext(InputStream inStream, OutputStream outStream) throws GSSException {
        throw unavailable();
    }

    @Override
    public byte[] acceptSecContext(byte[] inToken, int offset, int len) throws GSSException {
        accepted = Arrays.equals(INIT_TOKEN, Arrays.copyOfRange(inToken, offset, offset + len));
        return ACCEPT_TOKEN;
    }

    @Override
    public void acceptSecContext(InputStream inStream, OutputStream outStream) throws GSSException {
        throw unavailable();
    }

    @Override
    public boolean isEstablished() {
        return initialized || accepted;
    }

    @Override
    public void dispose() throws GSSException {
        // Nothing to do
    }

    @Override
    public int getWrapSizeLimit(int qop, boolean confReq, int maxTokenSize) throws GSSException {
        throw unavailable();
    }

    @Override
    public byte[] wrap(byte[] inBuf, int offset, int len, MessageProp msgProp) throws GSSException {
        throw unavailable();
    }

    @Override
    public void wrap(InputStream inStream, OutputStream outStream, MessageProp msgProp) throws GSSException {
        throw unavailable();
    }

    @Override
    public byte[] unwrap(byte[] inBuf, int offset, int len, MessageProp msgProp) throws GSSException {
        throw unavailable();
    }

    @Override
    public void unwrap(InputStream inStream, OutputStream outStream, MessageProp msgProp) throws GSSException {
        throw unavailable();
    }

    @Override
    public byte[] getMIC(byte[] inMsg, int offset, int len, MessageProp msgProp) throws GSSException {
        return MIC;
    }

    @Override
    public void getMIC(InputStream inStream, OutputStream outStream, MessageProp msgProp) throws GSSException {
        throw unavailable();
    }

    @Override
    public void verifyMIC(byte[] inToken, int tokOffset, int tokLen, byte[] inMsg, int msgOffset, int msgLen, MessageProp msgProp) throws GSSException {
        if (!Arrays.equals(MIC, Arrays.copyOfRange(inToken, tokOffset, tokOffset + tokLen))) {
            throw new GSSException(GSSException.BAD_MIC);
        }
    }

    @Override
    public void verifyMIC(InputStream tokStream, InputStream msgStream, MessageProp msgProp) throws GSSException {
        throw unavailable();
    }

    @Override
    public byte[] export() throws GSSException {
        throw unavailable();
    }

    @Override
    public void requestMutualAuth(boolean state) throws GSSException {
        this.mutualAuthState = state;
    }

    @Override
    public void requestInteg(boolean state) throws GSSException {
        this.integState = state;
    }

    @Override
    public void requestReplayDet(boolean state) throws GSSException {
        throw unavailable();
    }

    @Override
    public void requestSequenceDet(boolean state) throws GSSException {
        throw unavailable();
    }

    @Override
    public void requestCredDeleg(boolean state) throws GSSException {
        throw unavailable();
    }

    @Override
    public void requestAnonymity(boolean state) throws GSSException {
        throw unavailable();
    }

    @Override
    public void requestConf(boolean state) throws GSSException {
        throw unavailable();
    }

    @Override
    public void requestLifetime(int lifetime) throws GSSException {
        throw unavailable();
    }

    @Override
    public void setChannelBinding(ChannelBinding cb) throws GSSException {
        throw unavailable();
    }

    @Override
    public boolean getMutualAuthState() {
        return mutualAuthState;
    }

    @Override
    public boolean getIntegState() {
        return integState;
    }

    @Override
    public boolean getCredDelegState() {
        return false;
    }

    @Override
    public boolean getReplayDetState() {
        return false;
    }

    @Override
    public boolean getSequenceDetState() {
        return false;
    }

    @Override
    public boolean getAnonymityState() {
        return false;
    }

    @Override
    public boolean isTransferable() throws GSSException {
        return false;
    }

    @Override
    public boolean isProtReady() {
        return false;
    }

    @Override
    public boolean getConfState() {
        return false;
    }

    @Override
    public int getLifetime() {
        return INDEFINITE_LIFETIME;
    }

    @Override
    public GSSName getSrcName() throws GSSException {
        try {
            String hostname = InetAddress.getLocalHost().getCanonicalHostName();
            return new BogusGSSName("user@" + hostname, GSSName.NT_HOSTBASED_SERVICE);
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public GSSName getTargName() throws GSSException {
        throw unavailable();
    }

    @Override
    public Oid getMech() throws GSSException {
        return BogusGSSManager.KRB5_MECH;
    }

    @Override
    public GSSCredential getDelegCred() throws GSSException {
        throw unavailable();
    }

    @Override
    public boolean isInitiator() throws GSSException {
        return false;
    }

}
