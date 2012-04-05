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
package net.schmizz.sshj.userauth.password;

import java.io.IOException;
import java.io.Reader;

/** A password-protected resource */
public abstract class Resource<H> {

    private final H detail;

    public Resource(H handle) {
        this.detail = handle;
    }

    public H getDetail() {
        return detail;
    }

    public abstract Reader getReader()
            throws IOException;

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof Resource))
            return false;
        Resource resource = (Resource) o;
        return detail == null ? resource.detail == null : detail.equals(resource.detail);

    }

    @Override
    public int hashCode() {
        return detail != null ? detail.hashCode() : 0;
    }

    @Override
    public String toString() {
        return "[" + getClass().getSimpleName() + "] " + detail;
    }

}
