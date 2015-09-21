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
            return byteArrayOutputStream.toString("UTF-8");
        } finally {
            IOUtils.closeQuietly(fileInputStream);
        }
    }
}
