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

package net.schmizz.sshj.util;

import net.schmizz.sshj.common.Base64DecodingException;
import net.schmizz.sshj.common.Base64Decoder;

import java.io.IOException;

public class CorruptBase64 {
    private CorruptBase64() {
    }

    public static String corruptBase64(String source) throws IOException {
        while (true) {
            try {
                Base64Decoder.decode(source);
            } catch (Base64DecodingException e) {
                return source;
            }

            if (source.endsWith("=")) {
                source = source.substring(0, source.length() - 1);
            }
            source += "X";
        }
    }
}
