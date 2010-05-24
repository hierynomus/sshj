package net.schmizz.sshj.xfer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class LoggingTransferListener
        implements TransferListener {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final List<String> dirNames = new ArrayList<String>();
    private String base = "";
    private String name = "";
    private long size = -1;

    @Override
    public void startedDir(String name) {
        dirNames.add(name);
        size = -1;
        fixBase();
        log.info("started transferring directory `{}`", currentNode());
    }

    @Override
    public void startedFile(String name, long size) {
        this.name = name;
        this.size = size;
        log.info("started transferring file `{}` ({} bytes)", currentNode(), size);
    }

    @Override
    public void reportProgress(long transferred) {
        if (log.isDebugEnabled()) {
            log.debug("transferred {}% of `{}`", ((transferred * 100) / size), currentNode());
        }
    }

    @Override
    public void finishedFile() {
        log.info("finished transferring file `{}`", currentNode());
        name = "";
        size = -1;
    }

    @Override
    public void finishedDir() {
        log.info("finished transferring dir `{}`", currentNode());
        size = -1;
        dirNames.remove(dirNames.size() - 1);
        fixBase();
    }

    private void fixBase() {
        final StringBuilder qualifier = new StringBuilder();
        for (String parent : dirNames) {
            qualifier.append(parent).append("/");
        }
        base = qualifier.toString();
    }

    private String currentNode() {
        return base + name;
    }

}
