package net.schmizz.sshj.xfer;

import net.schmizz.sshj.common.StreamCopier;

public interface TransferListener
        extends StreamCopier.Listener {

    void startedDir(String name);

    void startedFile(String name, long size);

    void finishedFile();

    void finishedDir();

}