/*
 * Copyright 2010 Shikhar Bhushan
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
package net.schmizz.sshj.xfer;

import java.io.File;
import java.io.IOException;

public class FileTransferUtil {

    public static File getTargetDirectory(File f, String dirname) throws IOException {
        if (f.exists())
            if (f.isDirectory()) {
                if (!f.getName().equals(dirname))
                    f = new File(f, dirname);
            } else
                throw new IOException(f + " - already exists as a file; directory required");

        if (!f.exists() && !f.mkdir())
            throw new IOException("Failed to create directory: " + f);

        return f;
    }

    public static File getTargetFile(File f, String filename) throws IOException {
        if (f.isDirectory())
            f = new File(f, filename);

        if (!f.exists()) {
            if (!f.createNewFile())
                throw new IOException("Could not create: " + f);
        } else if (f.isDirectory())
            throw new IOException("A directory by the same name already exists: " + f);

        return f;
    }

}
