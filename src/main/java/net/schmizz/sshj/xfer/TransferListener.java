package net.schmizz.sshj.xfer;

import net.schmizz.sshj.common.StreamCopier;

public interface TransferListener {

    TransferListener directory(String name);

    StreamCopier.Listener file(String name, long size);

}