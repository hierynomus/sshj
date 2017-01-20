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
package com.hierynomus.sshj.transport.kex;

import net.schmizz.sshj.transport.digest.SHA256;
import net.schmizz.sshj.transport.digest.SHA384;
import net.schmizz.sshj.transport.digest.SHA512;

import static net.schmizz.sshj.transport.kex.DHGroupData.*;

/**
 * Set of KEX methods that are not in official RFCs but are supported by some SSH servers.
 */
@SuppressWarnings("PMD.MethodNamingConventions")
public class ExtendedDHGroups {
    public static DHGroups.Factory Group14SHA256AtSSH() {
        return new DHGroups.Factory("diffie-hellman-group14-sha256@ssh.com", P14, G, new SHA256.Factory());
    }

    public static DHGroups.Factory Group15SHA256() {
        return new DHGroups.Factory("diffie-hellman-group15-sha256", P15, G, new SHA256.Factory());
    }

    public static DHGroups.Factory Group15SHA256AtSSH() {
        return new DHGroups.Factory("diffie-hellman-group15-sha256@ssh.com", P15, G, new SHA256.Factory());
    }

    public static DHGroups.Factory Group15SHA384AtSSH() {
        return new DHGroups.Factory("diffie-hellman-group15-sha384@ssh.com", P15, G, new SHA384.Factory());
    }

    public static DHGroups.Factory Group16SHA256() {
        return new DHGroups.Factory("diffie-hellman-group16-sha256", P16, G, new SHA256.Factory());
    }

    public static DHGroups.Factory Group16SHA384AtSSH() {
        return new DHGroups.Factory("diffie-hellman-group16-sha384@ssh.com", P16, G, new SHA384.Factory());
    }

    public static DHGroups.Factory Group16SHA512AtSSH() {
        return new DHGroups.Factory("diffie-hellman-group16-sha512@ssh.com", P16, G, new SHA512.Factory());
    }

    public static DHGroups.Factory Group18SHA512AtSSH() {
        return new DHGroups.Factory("diffie-hellman-group18-sha512@ssh.com", P18, G, new SHA512.Factory());
    }
}
