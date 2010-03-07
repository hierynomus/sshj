/*
 * Copyright 2010 Shikhar Bhushan
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
package net.schmizz.sshj.transport.verification;

import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.SecurityUtils;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.security.PublicKey;

public class ConsoleKnownHostsVerifier
        extends OpenSSHKnownHosts {

    private static final String YES = "yes";
    private static final String NO = "no";

    private final Console console;

    public ConsoleKnownHostsVerifier(File khFile, Console console)
            throws IOException {
        super(khFile);
        this.console = console;
    }

    @Override
    protected boolean hostKeyUnverifiableAction(String hostname, PublicKey key) {
        console.printf("The authenticity of host '%s' can't be established.\n" +
                       "%s key fingerprint is %s.\n", hostname, KeyType.fromKey(key), SecurityUtils.getFingerprint(key));
        String response = console.readLine("Are you sure you want to continue connecting (yes/no)? ");
        while (!(response.equalsIgnoreCase(YES) || response.equalsIgnoreCase(NO))) {
            response = console.readLine("Please explicitly enter yes/no: ");
        }
        if (response.equalsIgnoreCase(YES)) {
            try {
                entries().add(new SimpleEntry(hostname, key));
                write();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return true;
        }
        return false;
    }

    @Override
    protected boolean hostKeyChangedAction(Entry entry, String hostname, PublicKey key)
            throws IOException {
        final KeyType type = KeyType.fromKey(key);
        final String fp = SecurityUtils.getFingerprint(key);
        final String path = khFile.getAbsolutePath();
        console.printf(
                "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n" +
                "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n" +
                "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n" +
                "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n" +
                "Someone could be eavesdropping on you right now (man-in-the-middle attack)!\n" +
                "It is also possible that the host key has just been changed.\n" +
                "The fingerprint for the %s key sent by the remote host is\n" +
                "%s.\n" +
                "Please contact your system administrator or" +
                "add correct host key in %s to get rid of this message.\n", type, fp, path);
        return false;
    }
}
