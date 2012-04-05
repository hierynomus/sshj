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

import net.schmizz.sshj.common.Buffer;

import java.util.Map;
import java.util.Map.Entry;

/** Various modes for a psuedo-terminal. They are meant to have integer parameters. */
public enum PTYMode {
    /**
     * Interrupt character; 255 if none. Similarly for the other characters. Not all of these characters are supported
     * on all systems.
     */
    VINTR(1),
    /** The quit character (sends SIGQUIT signal on POSIX systems). */
    VQUIT(2),
    /** Erase the character to left of the cursor. */
    VERASE(3),
    /** Kill the current input line. */
    VKILL(4),
    /** End-of-file character (sends EOF from the terminal). */
    VEOF(5),
    /** End-of-line character in addition to carriage return and/or linefeed. */
    VEOL(6),
    /** Additional end-of-line character. */
    VEOL2(7),
    /** Continues paused output (normally control-Q). */
    VSTART(8),
    /** Pauses output (normally control-S). */
    VSTOP(9),
    /** Suspends the current program. */
    VSUSP(10),
    /** Another suspend character. */
    VDSUSP(11),
    /** Reprints the current input line. */
    VREPRINT(12),
    /** Erases a word left of cursor. */
    VWERASE(13),
    /** Enter the next character typed literally, even if it is a special character. */
    VLNEXT(14),
    /** Character to flush output. */
    VFLUSH(15),
    /** Switch to a different shell layer. */
    VSWTCH(16),
    /** Prints system status line (load, command, pid, etc). */
    VSTATUS(17),
    /** Toggles the flushing of terminal output. */
    VDISCARD(18),
    /** The ignore parity flag. The parameter SHOULD be 0 if this flag is FALSE, and 1 if it is TRUE. */
    IGNPAR(30),
    /** Mark parity and framing errors. */
    PARMRK(31),
    /** Enable checking of parity errors. */
    INPCK(32),
    /** Strip 8th bit off characters. */
    ISTRIP(33),
    /** Map NL into CR on input. */
    INLCR(34),
    /** Ignore CR on input. */
    IGNCR(35),
    /** Map CR to NL on input. */
    ICRNL(36),
    /** Translate uppercase characters to lowercase. */
    IUCLC(37),
    /** Enable output flow control. */
    IXON(38),
    /** Any char will restart after stop. */
    IXANY(39),
    /** Enable input flow control. */
    IXOFF(40),
    /** Ring bell on input queue full. */
    IMAXBEL(41),
    /** Enable signals INTR, QUIT, [D]SUSP. */
    ISIG(50),
    /** Canonicalize input lines. */
    ICANON(51),
    /** Enable input and output of uppercase characters by preceding their lowercase equivalents with &quot;\&quot;. */
    XCASE(52),
    /** Enable echoing. */
    ECHO(53),
    /** Visually erase chars. */
    ECHOE(54),
    /** Kill character discards current line. */
    ECHOK(55),
    /** Echo NL even if ECHO is off. */
    ECHONL(56),
    /** Don't flush after interrupt. */
    NOFLSH(57),
    /** Stop background jobs from output. */
    TOSTOP(58),
    /** Enable extensions. */
    IEXTEN(59),
    /** Echo control characters as &circ;(Char). */
    ECHOCTL(60),
    /** Visual erase for line kill. */
    ECHOKE(61),
    /** Retype pending input. */
    PENDIN(62),
    /** Enable output processing. */
    OPOST(70),
    /** Convert lowercase to uppercase. */
    OLCUC(71),
    /** Map NL to CR-NL. */
    ONLCR(72),
    /** Translate carriage return to newline (output). */
    OCRNL(73),
    /** Translate newline to carriage return-newline (output). */
    ONOCR(74),
    /** Newline performs a carriage return (output). */
    ONLRET(75),
    /** 7 bit mode. */
    CS7(90),
    /** 8 bit mode. */
    CS8(91),
    /** Parity enable. */
    PARENB(92),
    /** Odd parity, else even. */
    PARODD(93),
    /** Specifies the input baud rate in bits per second. */
    TTY_OP_ISPEED(128),
    /** Specifies the output baud rate in bits per second. */
    TTY_OP_OSPEED(129);

    public static byte[] encode(Map<PTYMode, Integer> modes) {
        Buffer.PlainBuffer buf = new Buffer.PlainBuffer();
        for (Entry<PTYMode, Integer> entry : modes.entrySet()) {
            buf.putByte(entry.getKey().getOpcode());
            buf.putUInt32(entry.getValue());
        }
        buf.putByte((byte) 0);
        return buf.getCompactData();
    }

    private final byte opcode;

    private PTYMode(int opcode) {
        this.opcode = (byte) opcode;
    }

    public byte getOpcode() {
        return opcode;
    }

}