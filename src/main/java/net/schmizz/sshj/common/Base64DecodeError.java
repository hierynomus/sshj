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

package net.schmizz.sshj.common;

/**
 * A checked wrapper for all {@link IllegalArgumentException}, thrown by {@link java.util.Base64.Decoder}.
 *
 * @see Base64Decoder
 */
public class Base64DecodeError extends Exception {
    public Base64DecodeError(IllegalArgumentException cause) {
        super("Failed to decode base64: " + cause.getMessage(), cause);
    }
}