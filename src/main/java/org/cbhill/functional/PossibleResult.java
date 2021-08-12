/*
 * Copyright (C)2009 - SSHJ Contributors
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
package org.cbhill.functional;

/**
 * PossibleResult allows methods to return an object that encapsulates
 * Their outcome. The recipient can decide for themselves what to
 * do with it.
 *
 * @author : Bernie Day
 * @since : 8/12/21, Thu
 **/
public class PossibleResult<T> {
    public final Exception exception;
    public final T data;

    private PossibleResult(Exception exception, T data) {
        this.exception = exception;
        this.data = data;
    }

    /**
     *
     * @return -- there is data
     */
    public boolean isGood() {
        return data != null && exception == null;
    }

    /**
     *
     * @return -- there is exception data
     */
    public boolean isException() {
        return exception != null;
    }

    /**
     *
     * @return -- the data is any, or die trying
     */
    public T getData() {
        return data;
    }

    public String toString() {
        if (isGood()) return "Good data -- "+getData();
        else if (exception != null) return exception.getCause()+"\n";
        else return "No-Data";
    }

    /**
     * Data was produced
     * @param data -- This is the result of the operation
     * @param <T> -- The type of data
     * @return -- Data production was successful, return data
     */
    public static <T> PossibleResult<T> success(T data) {
        return new PossibleResult<>(null, data);
    }

    /**
     * Data was not produced
     * @param <T> -- the type of data we didn't find
     * @return -- no data and no exception
     */
    public static <T> PossibleResult<T>  noData() {
        return new PossibleResult<>(null, null);
    }

    /**
     *
     * @param x -- the exception
     * @param <T> -- The type of data asked for
     * @return -- the exception
     */
    public static <T> PossibleResult<T>  exception(Exception x) {
        return new PossibleResult<>(x, null);
    }
}
