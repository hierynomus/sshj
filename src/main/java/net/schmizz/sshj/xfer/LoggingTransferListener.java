package net.schmizz.sshj.xfer;

import net.schmizz.sshj.common.StreamCopier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class LoggingTransferListener
        implements TransferListener {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final String relPath;

    public LoggingTransferListener() {
        this("");
    }

    private LoggingTransferListener(String relPath) {
        this.relPath = relPath;
    }

    @Override
    public TransferListener directory(String name) {
        log.info("started transferring directory `{}`", name);
        return new LoggingTransferListener(relPath + name + "/");
    }

    @Override
    public StreamCopier.Listener file(final String name, final long size) {
        final String path = relPath + name;
        log.info("started transferring file `{}` ({} bytes)", path, size);
        return new StreamCopier.Listener() {
            @Override
            public void reportProgress(long transferred)
                    throws IOException {
                if (log.isDebugEnabled()) {
                    log.debug("transferred {}% of `{}`", ((transferred * 100) / size), path);
                }
            }
        };
    }

}
