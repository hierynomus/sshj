package net.schmizz.sshj.xfer;

public interface ProgressListener {

    void started(int item, boolean isDir);

    void progressed(long done, long total);

    void completed(int item);

}
