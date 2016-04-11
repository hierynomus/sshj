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
package net.schmizz.sshj.xfer.scp;

import java.util.LinkedHashMap;

/**
 * Command line to be sent to the remote SSH process to setup an SCP process in the correct mode.
 */
public class ScpCommandLine {
    private static final String SCP_COMMAND = "scp";
    private EscapeMode mode;

    enum Arg {
        SOURCE('f'),
        SINK('t'),
        RECURSIVE('r'),
        VERBOSE('v'),
        PRESERVE_TIMES('p'),
        QUIET('q'),
        LIMIT('l');

        private final char a;

        private Arg(char a) {
            this.a = a;
        }

        @Override
        public String toString() {
            return "-" + a;
        }
    }

    public enum EscapeMode {
        NoEscape,
        Space {
            @Override
            String escapedPath(String path) {
                return path.replace(" ", "\\ ");
            }
        },
        DoubleQuote {
            @Override
            String escapedPath(String path) {
                return "\"" + path.replace("\"", "\\\"") + "\"";
            }
        },
        SingleQuote {
            @Override
            String escapedPath(String path) {
                return "\'" + path.replace("'", "\\'") + "'";
            }
        };

        String escapedPath(String path) {
            return path;
        }
    }

    private LinkedHashMap<Arg, String> arguments = new LinkedHashMap<Arg, String>();
    private String path;

    ScpCommandLine() {
    }

    static ScpCommandLine with(Arg name) {
        return with(name, null, true);
    }

    static ScpCommandLine with(Arg name, String value) {
        return with(name, value, true);
    }

    static ScpCommandLine with(Arg name, boolean accept) {
        return with(name, null, accept);
    }

    static ScpCommandLine with(Arg name, String value, boolean accept) {
        ScpCommandLine commandLine = new ScpCommandLine();
        commandLine.addArgument(name, value, accept);
        return commandLine;
    }

    private void addArgument(Arg name, String value, boolean accept) {
        if (accept) {
            arguments.put(name, value);
        }
    }

    ScpCommandLine and(Arg name) {
        addArgument(name, null, true);
        return this;
    }

    ScpCommandLine and(Arg name, String value) {
        addArgument(name, value, true);
        return this;
    }

    ScpCommandLine and(Arg name, boolean accept) {
        addArgument(name, null, accept);
        return this;
    }

    ScpCommandLine and(Arg name, String value, boolean accept) {
        addArgument(name, value, accept);
        return this;
    }

    ScpCommandLine withPath(String path, EscapeMode mode) {
        this.path = path;
        this.mode = mode;
        return this;
    }

    String toCommandLine() {
        final StringBuilder cmd = new StringBuilder(SCP_COMMAND);
        for (Arg arg : arguments.keySet()) {
            cmd.append(" ").append(arg);
            String s = arguments.get(arg);
            if (s != null && !s.trim().isEmpty()) {
                cmd.append(s);
            }
        }
        cmd.append(" ");
        if (path == null || path.trim().isEmpty()) {
            cmd.append(".");
        } else {
            cmd.append(mode.escapedPath(path));
        }
        return cmd.toString();
    }
}
