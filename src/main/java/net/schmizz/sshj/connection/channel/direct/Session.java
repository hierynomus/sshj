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

import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.channel.Channel;
import net.schmizz.sshj.transport.TransportException;

import java.io.InputStream;
import java.util.Map;

/**
 * A {@code session} channel provides for execution of a remote {@link Command command}, {@link Shell shell} or {@link
 * Subsystem subsystem}. Before this requests like starting X11 forwarding, setting environment variables, allocating a
 * PTY etc. can be made.
 * <p/>
 * It is not legal to reuse a {@code session} channel for more than one of command, shell, or subsystem. Once one of
 * these has been started this instance's API is invalid and that of the {@link Command specific} {@link Shell targets}
 * {@link Subsystem returned} should be used.
 *
 * @see Command
 * @see Shell
 * @see Subsystem
 */
public interface Session
        extends Channel {

    /** Command API. */
    interface Command
            extends Channel {

        /** Returns the command's {@code stderr} stream. */
        InputStream getErrorStream();

        /**
         * If the command exit violently {@link #getExitSignal() with a signal}, an error message would have been
         * received and can be retrieved via this method. Otherwise, this method will return {@code null}.
         */
        String getExitErrorMessage();

        /**
         * Returns the {@link Signal signal} if the command exit violently, or {@code null} if this information was not
         * received.
         */
        Signal getExitSignal();

        /**
         * Returns the exit status of the command if it was received, or {@code null} if this information was not
         * received.
         */
        Integer getExitStatus();

        /**
         * If the command exit violently {@link #getExitSignal() with a signal}, information about whether a core dump
         * took place would have been received and can be retrieved via this method. Otherwise, this method will return
         * {@code null}.
         */
        Boolean getExitWasCoreDumped();

        /**
         * Send a signal to the remote command.
         *
         * @param signal the signal
         *
         * @throws TransportException if error sending the signal
         */
        void signal(Signal signal)
                throws TransportException;

    }

    /** Shell API. */
    interface Shell
            extends Channel {

        /**
         * Whether the client can do local flow control using {@code control-S} and {@code control-Q}.
         *
         * @return boolean value indicating whether 'client can do', or {@code null} if no such information was
         *         received
         */
        Boolean canDoFlowControl();

        /**
         * Sends a window dimension change message.
         *
         * @param cols   terminal width, columns
         * @param rows   terminal height, rows
         * @param width  terminal width, pixels
         * @param height terminal height, pixels
         *
         * @throws TransportException
         */
        void changeWindowDimensions(int cols, int rows, int width, int height)
                throws TransportException;

        /** Returns the shell's {@code stderr} stream. */
        InputStream getErrorStream();

        /**
         * Send a signal.
         *
         * @param signal the signal
         *
         * @throws TransportException if error sending the signal
         */
        void signal(Signal signal)
                throws TransportException;

    }

    /** Subsystem API. */
    interface Subsystem
            extends Channel {

        Integer getExitStatus();
    }

    /**
     * Allocates a default PTY. The default PTY is {@code "vt100"} with the echo modes disabled.
     *
     * @throws net.schmizz.sshj.connection.ConnectionException
     *
     * @throws TransportException
     */
    void allocateDefaultPTY()
            throws ConnectionException, TransportException;

    /**
     * Allocate a psuedo-terminal for this session.
     * <p/>
     * {@code 0} dimension parameters will be ignored by the server.
     *
     * @param term   {@code TERM} environment variable value (e.g., {@code vt100})
     * @param cols   terminal width, cols (e.g., 80)
     * @param rows   terminal height, rows (e.g., 24)
     * @param width  terminal width, pixels (e.g., 640)
     * @param height terminal height, pixels (e.g., 480)
     * @param modes
     *
     * @throws ConnectionException
     * @throws TransportException
     */
    void allocatePTY(String term, int cols, int rows, int width, int height, Map<PTYMode, Integer> modes)
            throws ConnectionException, TransportException;

    /**
     * Execute a remote command.
     *
     * @param command
     *
     * @return {@link Command} instance which should now be used
     *
     * @throws ConnectionException if the request to execute the command failed
     * @throws TransportException  if there is an error sending the request
     */
    Command exec(String command)
            throws ConnectionException, TransportException;

    /**
     * Request X11 forwarding.
     *
     * @param authProto  X11 authentication protocol name
     * @param authCookie X11 authentication cookie
     * @param screen     X11 screen number
     *
     * @throws ConnectionException if the request failed
     * @throws TransportException  if there was an error sending the request
     */
    void reqX11Forwarding(String authProto, String authCookie, int screen)
            throws ConnectionException,
                   TransportException;

    /**
     * Set an enviornment variable.
     *
     * @param name  name of the variable
     * @param value value to set
     *
     * @throws ConnectionException if the request failed
     * @throws TransportException  if there was an error sending the request
     */
    void setEnvVar(String name, String value)
            throws ConnectionException, TransportException;

    /**
     * Request a shell.
     *
     * @return {@link Shell} instance which should now be used
     *
     * @throws ConnectionException if the request failed
     * @throws TransportException  if there was an error sending the request
     */
    Shell startShell()
            throws ConnectionException, TransportException;

    /**
     * Request a subsystem.
     *
     * @param name subsystem name
     *
     * @return {@link Subsystem} instance which should now be used
     *
     * @throws ConnectionException if the request failed
     * @throws TransportException  if there was an error sending the request
     */
    Subsystem startSubsystem(String name)
            throws ConnectionException, TransportException;

}
