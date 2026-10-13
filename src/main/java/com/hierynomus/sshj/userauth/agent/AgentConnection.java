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
package com.hierynomus.sshj.userauth.agent;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * A duplex byte channel to a running SSH authentication agent.
 * <p>
 * sshj ships {@link UnixSocketAgentConnection} for the {@code SSH_AUTH_SOCK} unix-domain socket
 * used by OpenSSH on Linux and macOS. Implement this yourself to reach an agent over a different
 * transport, e.g. a Windows named pipe / Pageant, or a socket your application already owns.
 */
public interface AgentConnection extends Closeable {

    InputStream getInputStream() throws IOException;

    OutputStream getOutputStream() throws IOException;
}
