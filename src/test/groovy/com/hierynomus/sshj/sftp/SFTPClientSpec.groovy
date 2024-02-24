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
package com.hierynomus.sshj.sftp

import com.hierynomus.sshj.test.SshServerExtension
import com.hierynomus.sshj.test.util.FileUtil
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.sftp.FileMode
import net.schmizz.sshj.sftp.RemoteResourceInfo
import net.schmizz.sshj.sftp.SFTPClient
import org.junit.jupiter.api.extension.RegisterExtension
import spock.lang.Specification
import spock.lang.TempDir
import spock.lang.Unroll

import java.nio.file.Files
import java.nio.file.Path

import static org.codehaus.groovy.runtime.IOGroovyMethods.withCloseable

class SFTPClientSpec extends Specification {

    @RegisterExtension
    public SshServerExtension fixture = new SshServerExtension()


    @TempDir
    public Path temp

    @Unroll
    def "should copy #sourceType->#targetType if #targetExists with #named name"() {
        given:
        File src = source
        File dest = target

        when:
        doUpload(src, dest)

        then:
        exists.each { f ->
            if (dest.isDirectory()) {
                assert new File(dest, f).exists()
            } else {
                assert dest.exists()
            }
        }
        // Dest is also counted by recursiveCount if it is a dir
        exists.size() + (dest.isDirectory() ? 1 : 0) == recursiveCount(dest)

        cleanup:
        // Delete the temp directories
        recursiveDelete(source.getParentFile())
        recursiveDelete(target.getParentFile())

        where:
        source       | target                    || exists
        sourceTree() | existingTargetDir("dest") || ["toto.txt", "tata.txt", "tutu", "tutu/tutu.txt"]
        sourceTree() | newTargetDir("dest")      || ["toto.txt", "tata.txt", "tutu", "tutu/tutu.txt"]
        sourceTree() | existingTargetDir("toto") || ["toto.txt", "tata.txt", "tutu", "tutu/tutu.txt"]
        sourceTree() | newTargetDir("toto")      || ["toto.txt", "tata.txt", "tutu", "tutu/tutu.txt"]
        sourceFile() | existingTargetDir("dest") || ["toto.txt"]
        sourceFile() | newTargetFile("toto.txt") || ["toto.txt"]
        sourceFile() | newTargetFile("diff.txt") || ["diff.txt"]

        sourceType = source.isDirectory() ? "dir" : "file"
        targetType = target.isDirectory() ? "dir" : sourceType
        targetExists = target.exists() ? "exists" : "not exists"
        named = (target.name == source.name) ? "same" : "different"
    }


    def "should not throw exception on close before disconnect"() {
        given:
        File file = Files.createFile(temp.resolve("source.txt")).toFile()
        FileUtil.writeToFile(file, "This is the source")

        when:
        doUpload(file, temp.resolve("dest.txt").toFile())

        then:
        noExceptionThrown()
    }
//
//    def "should copy dir->dir if exists and same name"() {
//        given:
//        File srcDir = temp.newFolder("toto")
//        File destDir = temp.newFolder("dest", "toto")
//        FileUtil.writeToFile(new File(srcDir, "toto.txt"), "Toto file")
//
//        when:
//        doUpload(srcDir, destDir)
//
//        then:
//        destDir.exists()
//        !new File(destDir, "toto").exists()
//        new File(destDir, "toto.txt").exists()
//    }
//
//    def "should copy dir->dir if exists and different name"() {
//        given:
//        File srcDir = temp.newFolder("toto")
//        File destDir = temp.newFolder("dest")
//        FileUtil.writeToFile(new File(srcDir, "toto.txt"), "Toto file")
//
//        when:
//        doUpload(srcDir, destDir)
//
//        then:
//        destDir.exists()
//        new File(destDir, "toto.txt").exists()
//    }
//
//    def "should copy dir->dir if not exists and same name"() {
//        given:
//        File dd = temp.newFolder("dest")
//        File destDir = new File(dd, "toto")
//
//        when:
//        doUpload(srcDir, destDir)
//
//        then:
//        destDir.exists()
//        new File(destDir, "toto.txt").exists()
//    }
//
//    def "should copy dir->dir if not exists and different name"() {
//        given:
//        File srcDir = temp.newFolder("toto")
//        File destDir = new File(temp.getRoot(), "dest")
//        FileUtil.writeToFile(new File(srcDir, "toto.txt"), "Toto file")
//
//        when:
//        doUpload(srcDir, destDir)
//
//        then:
//        destDir.exists()
//        new File(destDir, "toto.txt").exists()
//    }

    def "should not merge same name subdirs (GH #252)"() {
        given:
        File toto = Files.createDirectory(temp.resolve("toto")).toFile()
        File tutu = mkdir(toto, "tutu")
        File toto2 = mkdir(toto, "toto")
        File dest = Files.createDirectory(temp.resolve("dest")).toFile()
        FileUtil.writeToFile(new File(toto, "toto.txt"), "Toto file")
        FileUtil.writeToFile(new File(tutu, "tototutu.txt"), "Toto/Tutu file")
        FileUtil.writeToFile(new File(toto2, "totototo.txt"), "Toto/Toto file")

        when:
        doUpload(toto, dest)

        then:
        new File(dest, "toto").exists()
        new File(dest, "toto.txt").exists()
        new File(dest, "tutu").exists()
        new File(dest, "tutu/tototutu.txt").exists()
        new File(dest, "toto").exists()
        new File(dest, "toto/totototo.txt").exists()
        !new File(dest, "totototo.txt").exists()
    }

    def "should mkdirs with existing parent path"() {
        given:
        SSHClient sshClient = fixture.setupConnectedDefaultClient()
        sshClient.authPassword("test", "test")
        SFTPClient ftp = sshClient.newSFTPClient()
        ftp.mkdir("dir1")

        when:
        ftp.mkdirs("dir1/dir2/dir3/dir4")

        then:
        ftp.statExistence("dir1/dir2/dir3/dir4") != null

        cleanup:
        ["dir1/dir2/dir3/dir4", "dir1/dir2/dir3", "dir1/dir2", "dir1"].each {
            ftp.rmdir(it)
        }
        ftp.close()
        sshClient.disconnect()
    }

    def "should stat root"() {
        given:
        SSHClient sshClient = fixture.setupConnectedDefaultClient()
        sshClient.authPassword("test", "test")
        SFTPClient ftp = sshClient.newSFTPClient()

        when:
        def attrs = ftp.statExistence("/")

        then:
        attrs.type == FileMode.Type.DIRECTORY
    }

    def "should support premature termination of listing"() {
        given:
        SSHClient sshClient = fixture.setupConnectedDefaultClient()
        sshClient.authPassword("test", "test")
        SFTPClient sftpClient = sshClient.newSFTPClient()

        final Path source = Files.createDirectory(temp.resolve("source")).toAbsolutePath()
        final Path destination = Files.createDirectory(temp.resolve("destination")).toAbsolutePath()
        final Path firstFile = Files.writeString(source.resolve("a_first.txt"), "first")
        final Path secondFile = Files.writeString(source.resolve("b_second.txt"), "second")
        final Path thirdFile = Files.writeString(source.resolve("c_third.txt"), "third")
        final Path fourthFile = Files.writeString(source.resolve("d_fourth.txt"), "fourth")
        sftpClient.put(firstFile.toString(), destination.resolve(firstFile.fileName).toString())
        sftpClient.put(secondFile.toString(), destination.resolve(secondFile.fileName).toString())
        sftpClient.put(thirdFile.toString(), destination.resolve(thirdFile.fileName).toString())
        sftpClient.put(fourthFile.toString(), destination.resolve(fourthFile.fileName).toString())

        def filesListed = 0
        RemoteResourceInfo expectedFile = null
        RemoteResourceSelector limitingSelector = new RemoteResourceSelector() {
            @Override
            RemoteResourceSelector.Result select(RemoteResourceInfo resource) {
                filesListed += 1

                switch(filesListed) {
                    case 1:
                        return RemoteResourceSelector.Result.CONTINUE
                    case 2:
                        expectedFile = resource
                        return RemoteResourceSelector.Result.ACCEPT
                    case 3:
                        return RemoteResourceSelector.Result.BREAK
                    default:
                        throw new AssertionError((Object) "Should NOT select any more resources")
                }
            }
        }

        when:
        def listingResult = sftpClient
                .ls(destination.toString(), limitingSelector);

        then:
        // first should be skipped by CONTINUE
        listingResult.contains(expectedFile) // second should be included by ACCEPT
        // third should be skipped by BREAK
        // fourth should be skipped by preceding BREAK
        listingResult.size() == 1

        cleanup:
        sftpClient.close()
        sshClient.disconnect()
    }

    private void doUpload(File src, File dest) throws IOException {
        SSHClient sshClient = fixture.setupConnectedDefaultClient()
        sshClient.authPassword("test", "test")
        try {
            withCloseable(sshClient.newSFTPClient()) { SFTPClient sftpClient ->
                sftpClient.put(src.getPath(), dest.getPath())
            }
        } finally {
            sshClient.disconnect()
        }
    }

    private File mkdir(File parent, String name) {
        File file = new File(parent, name)
        file.mkdirs()
        return file
    }

    private def sourceTree() {
        def tempDir = File.createTempDir()
        File srcDir = mkdir(tempDir, "toto")
        FileUtil.writeToFile(new File(srcDir, "toto.txt"), "Toto file")
        FileUtil.writeToFile(new File(srcDir, "tata.txt"), "Tata file")
        File tutuDir = mkdir(srcDir, "tutu")
        FileUtil.writeToFile(new File(tutuDir, "tutu.txt"), "Tutu file")
        return srcDir
    }

    private def sourceFile() {
        def tempDir = File.createTempDir()
        def totoFile = new File(tempDir, "toto.txt")
        FileUtil.writeToFile(totoFile, "Bare toto file")
        return totoFile
    }

    private def existingTargetDir(String name) {
        def tempDir = File.createTempDir("sftp", "tmp")
        tempDir.deleteOnExit()
        return mkdir(tempDir, name)
    }

    private def newTargetFile(String name) {
        def tempDir = File.createTempDir("sftp", "tmp")
        tempDir.deleteOnExit()
        return new File(tempDir, name)
    }

    private def newTargetDir(String name) {
        def tempDir = File.createTempDir("sftp", "tmp")
        tempDir.deleteOnExit()
        return new File(tempDir, name)
    }

    private int recursiveCount(File file) {
        if (file.isFile()) {
            return 1
        }
        File[] files = file.listFiles();
        if (files != null) {
            return 1 + (files.collect({ f -> recursiveCount(f) }).sum() as int)
        } else {
            return 1
        }
    }

    private void recursiveDelete(File file) {
        File[] files = file.listFiles();
        if (files != null) {
            for (File each : files) {
                recursiveDelete(each);
            }
        }
        file.delete();
    }
}
