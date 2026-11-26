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

import net.schmizz.sshj.common.SSHRuntimeException;

/**
 * Thrown by a security key signature when the {@link SecurityKeySigner} could not produce a signature, for
 * example because the user cancelled the touch or PIN prompt, entered a wrong PIN, the device timed out, or no
 * signer is attached to the key.
 * <p>
 * The {@link net.schmizz.sshj.signature.Signature} interface cannot declare checked exceptions, so this is
 * unchecked. Like any other failure to sign, authentication converts it into a
 * {@link net.schmizz.sshj.userauth.UserAuthException}, so that only the authentication attempt fails and the
 * connection stays usable for another method. The dedicated type tells callers that the authenticator, not the
 * JCA, failed.
 */
@SuppressWarnings("serial")
public class SecurityKeySigningException extends SSHRuntimeException {

    public SecurityKeySigningException(String message) {
        super(message);
    }

    public SecurityKeySigningException(String message, Throwable cause) {
        super(message, cause);
    }
}
