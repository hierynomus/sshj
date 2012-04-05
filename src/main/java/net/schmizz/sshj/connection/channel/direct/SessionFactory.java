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
package net.schmizz.sshj.connection.channel.direct;

import net.schmizz.sshj.common.SSHException;

/** A factory interface for creating SSH {@link Session session channels}. */
public interface SessionFactory {

    /**
     * Opens a {@code session} channel. The returned {@link Session} instance allows {@link Session#exec(String)
     * executing a remote command}, {@link Session#startSubsystem(String) starting a subsystem}, or {@link
     * Session#startShell() starting a shell}.
     *
     * @return the opened {@code session} channel
     *
     * @throws SSHException
     * @see Session
     */
    Session startSession()
            throws SSHException;

}
