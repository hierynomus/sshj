package net.schmizz.sshj.xfer.scp;

abstract class AbstractSCPClient {

    protected final SCPEngine engine;
    protected int bandwidthLimit;

    AbstractSCPClient(SCPEngine engine) {
        this.engine = engine;
    }

    AbstractSCPClient(SCPEngine engine, int bandwidthLimit) {
        this.engine = engine;
        this.bandwidthLimit = bandwidthLimit;
    }
}
