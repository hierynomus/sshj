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
 *
 * This file may incorporate work covered by the following copyright and
 * permission notice:
 *
 *     Licensed to the Apache Software Foundation (ASF) under one
 *     or more contributor license agreements.  See the NOTICE file
 *     distributed with this work for additional information
 *     regarding copyright ownership.  The ASF licenses this file
 *     to you under the Apache License, Version 2.0 (the
 *     "License"); you may not use this file except in compliance
 *     with the License.  You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *      Unless required by applicable law or agreed to in writing,
 *      software distributed under the License is distributed on an
 *      "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *      KIND, either express or implied.  See the License for the
 *      specific language governing permissions and limitations
 *      under the License.
 */
package net.schmizz.sshj.transport.kex;

import java.math.BigInteger;

/** Simple class holding the data for DH group key exchanges. */
public final class DHGroupData {

    public static final BigInteger G =
            new BigInteger("2");

    public static final BigInteger P1 =
            new BigInteger("1797693134862315907708391567937874531978602960487560117064444236841971802161585193" +
                                   "6894783379586492554150218056548598050364644054819923910005079287700335581663922955" +
                                   "3136239076508735759914822574862575007425302077447712589550957937778424442426617334" +
                                   "727629299387668709205606050270810842907692932019128194467627007");

    public static final BigInteger P14 =
            new BigInteger("3231700607131100730033891392642382824881794124114023911284200975140074170663435422" +
                                   "2619689417363569347117901737909704191754605873209195028853758986185622153212175412" +
                                   "5149017745202702357960782362488842461894775876411059286460994117232454266225221932" +
                                   "3054091903768052423551912567971587011700105805587765103886184728025797605490356973" +
                                   "2561526167081339361799541336476559160368317896729073178384589680639671900977202194" +
                                   "1686472258710314113364293195361934716365332097170774482279885885653692086452966360" +
                                   "7725026895550592836275112117409697299806841055435958486658329164213621823107899099" +
                                   "9448652468262416972035911852507045361090559");

}
