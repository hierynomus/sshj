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

import com.hierynomus.sshj.test.SshFixture
import com.hierynomus.sshj.test.util.FileUtil
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.sftp.FileMode
import net.schmizz.sshj.sftp.SFTPClient
import org.junit.Rule
import org.junit.rules.TemporaryFolder
import spock.lang.Specification
import spock.lang.Unroll

import static org.codehaus.groovy.runtime.IOGroovyMethods.withCloseable

class SFTPClientSpec extends Specification {

    @Rule
    public SshFixture fixture = new SshFixture()

    @Rule
    public TemporaryFolder temp = new TemporaryFolder()

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
        File file = temp.newFile("source.txt")
        FileUtil.writeToFile(file, "This is the source")

        when:
        doUpload(file, temp.newFile("dest.txt"))

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
        File toto = temp.newFolder("toto")
        File tutu = mkdir(toto, "tutu")
        File toto2 = mkdir(toto, "toto")
        File dest = temp.newFolder("dest")
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
