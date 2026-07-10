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
package com.hierynomus.sshj.userauth.fido;

import java.io.IOException;

/**
 * Service provider interface for signing with an OpenSSH FIDO/U2F security key (an
 * {@code sk-ecdsa-sha2-nistp256@openssh.com} or {@code sk-ssh-ed25519@openssh.com} key).
 * <p>
 * sshj cannot talk to a hardware authenticator on its own: there is no pure-Java USB-HID / CTAP
 * stack. The embedding application supplies one of these to bridge to the hardware - for example
 * via libfido2, a platform WebAuthn API, or by delegating to a running ssh-agent. Given the
 * challenge to sign, the application string and the credential (key handle), an implementation
 * makes the authenticator produce an assertion and returns the device's signature plus the flags
 * and counter that the authenticator reported.
 * <p>
 * Note: when a {@code ssh-agent} holds the security key, you do not need this interface at all - the
 * agent returns a fully formed SSH signature. Use the {@code com.hierynomus.sshj.userauth.agent}
 * support instead. This SPI is for applications that drive the authenticator themselves.
 *
 * @see <a href="https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f">PROTOCOL.u2f</a>
 */
public interface SecurityKeySigner {

    /**
     * Produce a FIDO assertion over the given challenge.
     *
     * @param request the challenge, application and credential to sign with
     * @return the authenticator's response (signature, flags and counter)
     * @throws IOException if the authenticator could not be reached or declined to sign
     */
    SecurityKeySignatureData sign(SecurityKeySigningRequest request) throws IOException;
}
