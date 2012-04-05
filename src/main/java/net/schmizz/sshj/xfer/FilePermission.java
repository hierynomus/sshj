/*
 * Copyright 2010-2012 sshj contributors
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
package net.schmizz.sshj.xfer;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public enum FilePermission {

    /** read permission, owner */
    USR_R(00400),
    /** write permission, owner */
    USR_W(00200),
    /** execute/search permission, owner */
    USR_X(00100),
    /** read permission, group */
    GRP_R(00040),
    /** write permission, group */
    GRP_W(00020),
    /** execute/search permission, group */
    GRP_X(00010),
    /** read permission, others */
    OTH_R(00004),
    /** write permission, others */
    OTH_W(00002),
    /** execute/search permission, group */
    OTH_X(00001),
    /** set-user-ID on execution */
    SUID(04000),
    /** set-group-ID on execution */
    SGID(02000),
    /** on directories, restricted deletion flag */
    STICKY(01000),
    // Composite:
    /** read, write, execute/search by user */
    USR_RWX(USR_R, USR_W, USR_X),
    /** read, write, execute/search by group */
    GRP_RWX(GRP_R, GRP_W, GRP_X),
    /** read, write, execute/search by other */
    OTH_RWX(OTH_R, OTH_W, OTH_X);

    private final int val;

    private FilePermission(int val) {
        this.val = val;
    }

    private FilePermission(FilePermission... perms) {
        int val = 0;
        for (FilePermission perm : perms)
            val |= perm.val;
        this.val = val;
    }

    public boolean isIn(int mask) {
        return (mask & val) == val;
    }

    public static Set<FilePermission> fromMask(int mask) {
        final List<FilePermission> perms = new LinkedList<FilePermission>();
        for (FilePermission p : FilePermission.values())
            if (p.isIn(mask))
                perms.add(p);
        return new HashSet<FilePermission>(perms);
    }

    public static int toMask(Set<FilePermission> perms) {
        int mask = 0;
        for (FilePermission p : perms)
            mask |= p.val;
        return mask;
    }

}