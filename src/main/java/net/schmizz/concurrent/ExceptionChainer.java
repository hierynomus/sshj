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
package net.schmizz.concurrent;

/**
 * Chains an exception to desired type. For example: </p>
 * <p/>
 * <pre>
 * ExceptionChainer&lt;SomeException&gt; chainer = new ExceptionChainer&lt;SomeException&gt;()
 * {
 *     public SomeException chain(Throwable t)
 *     {
 *         if (t instanceof SomeException)
 *             return (SomeException) t;
 *         else
 *             return new SomeExcepion(t);
 *     }
 * };
 * </pre>
 *
 * @param <Z> Throwable type
 */
public interface ExceptionChainer<Z extends Throwable> {

    Z chain(Throwable t);

}