package com.hierynomus.sshj.test.util;

import net.schmizz.sshj.common.IOUtils;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;

public class FileUtil {

    public static void writeToFile(File f, String content) throws IOException {
        FileWriter w = new FileWriter(f);
        try {
            w.write(content);
        } finally {
            IOUtils.closeQuietly(w);
        }
    }
}
