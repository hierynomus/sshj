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
package com.hierynomus.sshj.sftp;

import com.hierynomus.sshj.test.SshServerExtension;
import com.hierynomus.sshj.test.util.FileUtil;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.sftp.FileMode;
import net.schmizz.sshj.sftp.FileAttributes;
import net.schmizz.sshj.sftp.RemoteResourceInfo;
import net.schmizz.sshj.sftp.SFTPClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * SFTPClient tests against an in-process SSH server that serves the local file system.
 */
class SFTPClientServerTest {

    @RegisterExtension
    public SshServerExtension fixture = new SshServerExtension();

    @TempDir
    Path temp;

    private SSHClient sshClient;
    private SFTPClient sftp;

    /**
     * The fixture manages a single client, so tests either use this one or {@link #doUpload}, not both.
     */
    private void connect() throws IOException {
        sshClient = fixture.setupConnectedDefaultClient();
        sshClient.authPassword("test", "test");
        sftp = sshClient.newSFTPClient();
    }

    @AfterEach
    void disconnect() throws IOException {
        if (sftp != null) {
            sftp.close();
        }
        if (sshClient != null) {
            sshClient.disconnect();
        }
    }

    static Stream<Arguments> uploadCases() {
        List<String> tree = Arrays.asList("toto.txt", "tata.txt", "tutu", "tutu/tutu.txt");
        List<String> file = Arrays.asList("toto.txt");
        return Stream.of(
                Arguments.of("tree", "existingDir", "dest", tree),
                Arguments.of("tree", "newDir", "dest", tree),
                Arguments.of("tree", "existingDir", "toto", tree),
                Arguments.of("tree", "newDir", "toto", tree),
                Arguments.of("file", "existingDir", "dest", file),
                Arguments.of("file", "newFile", "toto.txt", file),
                Arguments.of("file", "newFile", "diff.txt", Arrays.asList("diff.txt")));
    }

    @ParameterizedTest(name = "should copy {0} to {1} {2}")
    @MethodSource("uploadCases")
    void shouldUpload(String sourceKind, String targetKind, String targetName, List<String> exists)
            throws IOException {
        File src = sourceKind.equals("tree") ? sourceTree() : sourceFile();
        Path targetParent = Files.createDirectories(temp.resolve("target"));
        File dest = targetParent.resolve(targetName).toFile();
        if (targetKind.equals("existingDir")) {
            assertTrue(dest.mkdirs());
        }

        doUpload(src, dest);

        for (String f : exists) {
            if (dest.isDirectory()) {
                assertTrue(new File(dest, f).exists(), f + " should exist in " + dest);
            } else {
                assertTrue(dest.exists(), dest + " should exist");
            }
        }
        // Dest is also counted by recursiveCount if it is a dir
        assertEquals(recursiveCount(dest), exists.size() + (dest.isDirectory() ? 1 : 0));
    }

    @Test
    void shouldNotThrowExceptionOnCloseBeforeDisconnect() throws IOException {
        File file = Files.createFile(temp.resolve("source.txt")).toFile();
        FileUtil.writeToFile(file, "This is the source");

        assertDoesNotThrow(() -> doUpload(file, temp.resolve("dest.txt").toFile()));
    }

    @Test
    void shouldNotMergeSameNameSubdirs_GH252() throws IOException {
        File toto = Files.createDirectory(temp.resolve("toto")).toFile();
        File tutu = mkdir(toto, "tutu");
        File toto2 = mkdir(toto, "toto");
        File dest = Files.createDirectory(temp.resolve("dest")).toFile();
        FileUtil.writeToFile(new File(toto, "toto.txt"), "Toto file");
        FileUtil.writeToFile(new File(tutu, "tototutu.txt"), "Toto/Tutu file");
        FileUtil.writeToFile(new File(toto2, "totototo.txt"), "Toto/Toto file");

        doUpload(toto, dest);

        assertTrue(new File(dest, "toto").exists());
        assertTrue(new File(dest, "toto.txt").exists());
        assertTrue(new File(dest, "tutu").exists());
        assertTrue(new File(dest, "tutu/tototutu.txt").exists());
        assertTrue(new File(dest, "toto/totototo.txt").exists());
        assertFalse(new File(dest, "totototo.txt").exists());
    }

    @Test
    void shouldMkdirsWithExistingParentPath() throws IOException {
        connect();
        Path base = temp.resolve("dir1");
        sftp.mkdir(base.toString());

        sftp.mkdirs(base.resolve("dir2/dir3/dir4").toString());

        assertNotNull(sftp.statExistence(base.resolve("dir2/dir3/dir4").toString()));
    }

    @Test
    void shouldStatRoot() throws IOException {
        connect();
        FileAttributes attrs = sftp.statExistence("/");

        assertEquals(FileMode.Type.DIRECTORY, attrs.getType());
    }

    @Test
    void shouldSupportPrematureTerminationOfListing() throws IOException {
        connect();
        final Path source = Files.createDirectory(temp.resolve("source")).toAbsolutePath();
        final Path destination = Files.createDirectory(temp.resolve("destination")).toAbsolutePath();
        for (String name : new String[]{"a_first.txt", "b_second.txt", "c_third.txt", "d_fourth.txt"}) {
            Path file = Files.writeString(source.resolve(name), name);
            sftp.put(file.toString(), destination.resolve(file.getFileName().toString()).toString());
        }

        final AtomicInteger filesListed = new AtomicInteger();
        final AtomicReference<RemoteResourceInfo> expectedFile = new AtomicReference<>();
        RemoteResourceSelector limitingSelector = resource -> {
            switch (filesListed.incrementAndGet()) {
                case 1:
                    return RemoteResourceSelector.Result.CONTINUE;
                case 2:
                    expectedFile.set(resource);
                    return RemoteResourceSelector.Result.ACCEPT;
                case 3:
                    return RemoteResourceSelector.Result.BREAK;
                default:
                    fail("Should NOT select any more resources");
                    return RemoteResourceSelector.Result.BREAK;
            }
        };

        List<RemoteResourceInfo> listingResult = sftp.ls(destination.toString(), limitingSelector);

        // first should be skipped by CONTINUE, second included by ACCEPT,
        // third skipped by BREAK, fourth skipped by the preceding BREAK
        assertEquals(1, listingResult.size());
        assertTrue(listingResult.contains(expectedFile.get()));
    }

    private void doUpload(File src, File dest) throws IOException {
        SSHClient client = fixture.setupConnectedDefaultClient();
        client.authPassword("test", "test");
        try (SFTPClient sftpClient = client.newSFTPClient()) {
            sftpClient.put(src.getPath(), dest.getPath());
        } finally {
            client.disconnect();
        }
    }

    private File mkdir(File parent, String name) {
        File file = new File(parent, name);
        assertTrue(file.mkdirs());
        return file;
    }

    private File sourceTree() throws IOException {
        File srcDir = mkdir(Files.createDirectories(temp.resolve("source-tree")).toFile(), "toto");
        FileUtil.writeToFile(new File(srcDir, "toto.txt"), "Toto file");
        FileUtil.writeToFile(new File(srcDir, "tata.txt"), "Tata file");
        File tutuDir = mkdir(srcDir, "tutu");
        FileUtil.writeToFile(new File(tutuDir, "tutu.txt"), "Tutu file");
        return srcDir;
    }

    private File sourceFile() throws IOException {
        File totoFile = new File(Files.createDirectories(temp.resolve("source-file")).toFile(), "toto.txt");
        FileUtil.writeToFile(totoFile, "Bare toto file");
        return totoFile;
    }

    private static int recursiveCount(File file) {
        if (file.isFile()) {
            return 1;
        }
        File[] files = file.listFiles();
        int count = 1;
        if (files != null) {
            for (File f : files) {
                count += recursiveCount(f);
            }
        }
        return count;
    }
}
