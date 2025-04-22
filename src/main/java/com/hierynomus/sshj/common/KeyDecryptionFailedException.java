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
package com.hierynomus.sshj.common;

import java.io.IOException;

/**
 * Thrown when a key file could not be decrypted correctly, e.g. if its checkInts differed in the case of an OpenSSH
 * key file.
 */
@SuppressWarnings("serial")
public class KeyDecryptionFailedException extends IOException {

    public static final String MESSAGE = "Decryption of the key failed. A supplied passphrase may be incorrect.";

    public KeyDecryptionFailedException(final String message) {
        super(message);
    }

    public KeyDecryptionFailedException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public KeyDecryptionFailedException(IOException cause) {
        super(MESSAGE, cause);
    }

}
