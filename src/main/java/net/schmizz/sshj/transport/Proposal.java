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
package net.schmizz.sshj.transport;

import com.hierynomus.sshj.key.KeyAlgorithm;
import com.hierynomus.sshj.key.KeyAlgorithms;
import net.schmizz.sshj.Config;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

class Proposal {

    private final List<String> kex;
    private final List<String> sig;
    private final List<String> c2sCipher;
    private final List<String> s2cCipher;
    private final List<String> c2sMAC;
    private final List<String> s2cMAC;
    private final List<String> c2sComp;
    private final List<String> s2cComp;
    private final SSHPacket packet;

    public Proposal(Config config, List<String> knownHostAlgs, boolean initialKex) {
        kex = Factory.Named.Util.getNames(config.getKeyExchangeFactories());
        if (initialKex) {
            kex.add("kex-strict-c-v00@openssh.com");
        }
        sig = filterKnownHostKeyAlgorithms(config.getKeyAlgorithms(), knownHostAlgs);
        c2sCipher = s2cCipher = Factory.Named.Util.getNames(config.getCipherFactories());
        c2sMAC = s2cMAC = Factory.Named.Util.getNames(config.getMACFactories());
        c2sComp = s2cComp = Factory.Named.Util.getNames(config.getCompressionFactories());

        packet = new SSHPacket(Message.KEXINIT);

        // Put cookie
        packet.ensureCapacity(16);
        config.getRandomFactory().create().fill(packet.array(), packet.wpos(), 16);
        packet.wpos(packet.wpos() + 16);

        // Put algorithm lists
        packet.putString(toCommaString(kex));
        packet.putString(toCommaString(sig));
        packet.putString(toCommaString(c2sCipher));
        packet.putString(toCommaString(s2cCipher));
        packet.putString(toCommaString(c2sMAC));
        packet.putString(toCommaString(s2cMAC));
        packet.putString(toCommaString(c2sComp));
        packet.putString(toCommaString(s2cComp));
        packet.putString("");
        packet.putString("");

        packet.putBoolean(false); // Optimistic next packet does not follow
        packet.putUInt32(0); // "Reserved" for future by spec
    }

    public Proposal(SSHPacket packet)
            throws TransportException {
        this.packet = packet;
        final int savedPos = packet.rpos();
        packet.rpos(packet.rpos() + 17); // Skip message ID & cookie
        try {
            kex = fromCommaString(packet.readString());
            sig = fromCommaString(packet.readString());
            c2sCipher = fromCommaString(packet.readString());
            s2cCipher = fromCommaString(packet.readString());
            c2sMAC = fromCommaString(packet.readString());
            s2cMAC = fromCommaString(packet.readString());
            c2sComp = fromCommaString(packet.readString());
            s2cComp = fromCommaString(packet.readString());
        } catch (Buffer.BufferException be) {
            throw new TransportException(be);
        }
        packet.rpos(savedPos);
    }

    public List<String> getKeyExchangeAlgorithms() {
        return kex;
    }

    public boolean isStrictKeyExchangeSupportedByServer() {
        return kex.contains("kex-strict-s-v00@openssh.com");
    }

    public List<String> getHostKeyAlgorithms() {
        return sig;
    }

    public List<String> getClient2ServerCipherAlgorithms() {
        return c2sCipher;
    }

    public List<String> getServer2ClientCipherAlgorithms() {
        return s2cCipher;
    }

    public List<String> getClient2ServerMACAlgorithms() {
        return c2sMAC;
    }

    public List<String> getServer2ClientMACAlgorithms() {
        return s2cMAC;
    }

    public List<String> getClient2ServerCompressionAlgorithms() {
        return c2sComp;
    }

    public List<String> getServer2ClientCompressionAlgorithms() {
        return s2cComp;
    }

    public SSHPacket getPacket() {
        return new SSHPacket(packet);
    }

    public NegotiatedAlgorithms negotiate(Proposal other)
            throws TransportException {
        return new NegotiatedAlgorithms(
                firstMatch("KeyExchangeAlgorithms", this.getKeyExchangeAlgorithms(), other.getKeyExchangeAlgorithms()),
                firstMatch("HostKeyAlgorithms", this.getHostKeyAlgorithms(), other.getHostKeyAlgorithms()),
                firstMatch("Client2ServerCipherAlgorithms", this.getClient2ServerCipherAlgorithms(),
                        other.getClient2ServerCipherAlgorithms()),
                firstMatch("Server2ClientCipherAlgorithms", this.getServer2ClientCipherAlgorithms(),
                        other.getServer2ClientCipherAlgorithms()),
                firstMatch("Client2ServerMACAlgorithms", this.getClient2ServerMACAlgorithms(),
                        other.getClient2ServerMACAlgorithms()),
                firstMatch("Server2ClientMACAlgorithms", this.getServer2ClientMACAlgorithms(),
                        other.getServer2ClientMACAlgorithms()),
                firstMatch("Client2ServerCompressionAlgorithms", this.getClient2ServerCompressionAlgorithms(),
                        other.getClient2ServerCompressionAlgorithms()),
                firstMatch("Server2ClientCompressionAlgorithms", this.getServer2ClientCompressionAlgorithms(),
                        other.getServer2ClientCompressionAlgorithms())
        );
    }

    private List<String> filterKnownHostKeyAlgorithms(List<Factory.Named<KeyAlgorithm>> configuredKeyAlgorithms, List<String> knownHostKeyAlgorithms) {
        if (knownHostKeyAlgorithms == null || knownHostKeyAlgorithms.isEmpty()) {
            return Factory.Named.Util.getNames(configuredKeyAlgorithms);
        }

        // A known_hosts entry only records the host key *type*: an RSA host key is always stored as
        // "ssh-rsa", regardless of whether the server signs with ssh-rsa, rsa-sha2-256 or rsa-sha2-512.
        // Matching the stored name against the configured signature algorithm names would therefore only
        // ever promote the legacy ssh-rsa and bury the rsa-sha2-* algorithms. Match on the key type
        // instead, so every configured signature algorithm for a known key type is preferred while
        // keeping the configured order (which prefers rsa-sha2-* over ssh-rsa).
        Set<KeyType> knownHostKeyTypes = EnumSet.noneOf(KeyType.class);
        for (String knownHostKeyAlgorithm : knownHostKeyAlgorithms) {
            knownHostKeyTypes.add(KeyType.fromString(knownHostKeyAlgorithm));
        }
        knownHostKeyTypes.remove(KeyType.UNKNOWN);

        List<String> preferredAlgorithms = new ArrayList<String>();
        List<String> otherAlgorithms = new ArrayList<String>();

        for (Factory.Named<KeyAlgorithm> configuredKeyAlgorithm : configuredKeyAlgorithms) {
            if (knownHostKeyTypes.contains(keyTypeOf(configuredKeyAlgorithm))) {
                preferredAlgorithms.add(configuredKeyAlgorithm.getName());
            } else {
                otherAlgorithms.add(configuredKeyAlgorithm.getName());
            }
        }

        preferredAlgorithms.addAll(otherAlgorithms);

        return preferredAlgorithms;
    }

    private static KeyType keyTypeOf(Factory.Named<KeyAlgorithm> keyAlgorithm) {
        if (keyAlgorithm instanceof KeyAlgorithms.Factory) {
            return ((KeyAlgorithms.Factory) keyAlgorithm).getKeyType();
        }
        return KeyType.fromString(keyAlgorithm.getName());
    }

    private static String firstMatch(String ofWhat, List<String> a, List<String> b)
            throws TransportException {
        for (String aa : a) {
            if (b.contains(aa)) {
                return aa;
            }
        }
        throw new TransportException("Unable to reach a settlement of " + ofWhat + ": " + a + " and " + b);
    }

    private static String toCommaString(List<String> sl) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        for (String s : sl) {
            if (i++ != 0) {
                sb.append(",");
            }
            sb.append(s);
        }
        return sb.toString();
    }

    private static List<String> fromCommaString(String s) {
        return Arrays.asList(s.split(","));
    }

}
