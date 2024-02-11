package com.hierynomus.sshj.sftp;

import com.hierynomus.sshj.sftp.RemoteResourceSelector.Result;
import net.schmizz.sshj.sftp.RemoteResourceFilter;

public class RemoteResourceFilterConverter {

    public static RemoteResourceSelector selectorFrom(RemoteResourceFilter filter) {
        return resource -> filter.accept(resource) ? Result.ACCEPT : Result.CONTINUE;
    }
}
