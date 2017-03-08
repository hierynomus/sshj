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
package com.hierynomus.sshj.test.util;

import net.schmizz.sshj.common.IOUtils;

import java.io.*;

public class FileUtil {

    public static void writeToFile(File f, String content) throws IOException {
        FileWriter w = new FileWriter(f);
        try {
            w.write(content);
        } finally {
            IOUtils.closeQuietly(w);
        }
    }

    public static String readFromFile(File f) throws IOException {
        FileInputStream fileInputStream = new FileInputStream(f);
        try {
            ByteArrayOutputStream byteArrayOutputStream = IOUtils.readFully(fileInputStream);
            return byteArrayOutputStream.toString(IOUtils.UTF8.displayName());
        } finally {
            IOUtils.closeQuietly(fileInputStream);
        }
    }
}
