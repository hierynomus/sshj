package net.schmizz.sshj.xfer.scp;

public class SCPRemoteException extends SCPException
{
    private final String remoteMessage;

    public SCPRemoteException(String message, String remoteMessage) {
        super(message);
        this.remoteMessage = remoteMessage;
    }

    public String getRemoteMessage() {
        return remoteMessage;
    }
}
