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
package net.schmizz.sshj.keyprovider;

import com.hierynomus.sshj.userauth.keyprovider.OpenSSHKeyV1KeyFile;
import net.schmizz.sshj.userauth.keyprovider.PKCS8KeyFile;
import net.schmizz.sshj.userauth.keyprovider.PuTTYKeyFile;
import net.schmizz.sshj.util.CorruptBase64;
import net.schmizz.sshj.util.UnitTestPasswordFinder;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

import static java.lang.Math.min;
import static org.junit.jupiter.api.Assertions.*;

public class PuTTYKeyFileTest {

    final static String ppk8192 = "PuTTY-User-Key-File-2: ssh-rsa\n" +
            "Encryption: none\n" +
            "Comment: imported-openssh-key\n" +
            "Public-Lines: 22\n" +
            "AAAAB3NzaC1yc2EAAAADAQABAAAEAQCcasi2SDVGvty6az32C3Uc3F4d8icjefnN\n" +
            "YCaDnBIRQjczX118dT/nG2rEMygR/cgCxmZgcySC7vo5KUNjJhxCMHa5u4H0CVdy\n" +
            "Raey2AOZBfLECjzuXSaakeMCIqyT6IywUBEFnkN6aUesyQtUUf1hR5iWHwPUmJPO\n" +
            "uYLlE4uYnK5hkeH8fSEbYVPcPiBnrHtRk+zh9MF0RR6tK0Gcms5eLfF2V2MNytvU\n" +
            "FnAySqX8mYISeJrg7v41PxtoEsAhGE88h4XAYX57uB4ewwTWQOlbBVgAutLybyLG\n" +
            "rxbw+cDuC3ZOuxU78u5PykcS/mkE2wu1jUtdnCzAmNN8XobAft0wggiEZUBc+t9D\n" +
            "2NmezZFU62SEkjxOWX/idDQrCQ8au8RQZhIgLYusGXDeeYFoPDk/4ObBxz3YkuTu\n" +
            "UqzVTYwoUslTe8cz5J+hDGPeTudkt1K4uXa+3weXrzj0BnSYvGb01bfoam8lShdl\n" +
            "MBg5hmow0ZjE6AvJgdttu+9SKvIp+jGQ2v2fv/m/LmGBKgZ5yslGJb6hhNf7MA5S\n" +
            "ewgHuAk8kfZ9yZIa3UcQDim8yxOkB/Y3885MFpdZqg3XNPCNo0s1SimGGRbngWwg\n" +
            "AxhKT24OzQ+WZn+rU7mlXHT4RehrYNKNukZlwqnSksg+TJ1ZGoj8mfUbAHmz0UnB\n" +
            "DQ7dpNP1DhAKxiFjgHfkDfmF4Bic7I1eHSesigCKImH7Zoomp1NcH0bub3h+Owyp\n" +
            "2fk5evgMBtuGvGGFuCzgyZeeiX6hzOgKyaqCML88OgNSjSMFkdiBYd0rwufimkID\n" +
            "v+vH1uIEcVZ69sn8xg0Vh7U/0aB2mai0EYcDuTa78gqkeSGp8AS+IgahgdwV/HQX\n" +
            "aLC/QFRgFb/NX2YmzKsVYWdObBamkbaJAOfrXb5vEuAyU2aRQouqKH4tYDNpkBYg\n" +
            "8KCq9A/8z8sS1Gwe3UHU9gZOEuTAI7JQQCN7E3U3JuuCFks2jAoh7WE3KxqEu9Lq\n" +
            "sMJn9YRobGyPPMMcQJSAqMUpwEyup8ovI/3v5NRvw+ZSiM4wHyYqzODJu/U6H5Cj\n" +
            "wq+MFCg4JcalRA/qKG4P9QVD9MfyqcX/AYWhdYj18BqstwUVtonhT0kMkKBx9ggU\n" +
            "g/TvVKePf/wX0glqXXw59I1EIzCnxL8QWMkULDkk5GvzSrGFpR04IdOzsz5DMdL3\n" +
            "p8bXOHK+04Rd/VG8w/f7eLfYid875B7m+kG9TKQzAT3lc8cmJ98gRzCG+pTIpzVB\n" +
            "QM2nj4f8DenS1uAO23cXICR9Zyo98/dCv0xYc7g0Gp5HxppRuNLga9bBSg5dferT\n" +
            "QvmP/MTgeNxiKepKFLakVT0MiM6QUlGfV35F6vDL1oQnQlp4OD7H\n" +
            "Private-Lines: 54\n" +
            "AAAEAEM55e/qEvPH/kgk5WmFPR1dXRoTxFyMBSAOzh7MijtesSjkOOLP5donP3j5\n" +
            "36Pz5e3DZabYdf3MRkEhCfRoIccU20IyY8UF6s6TP2MvUkSHePJm0A9Ge9v9DYsS\n" +
            "agfb7/OrRdWbUrce3o5Vjgf8gSE5S0xiIhxSQ1ybALYB84Jw/MW0lGMXSI5jA07q\n" +
            "aLUGPa4vHKV0s1yMhIW6zKVJJ570sg3BuzHnWRnLVwdWbAan126m5TH9pcYuzFGr\n" +
            "lWXj89I5EPRBMsJrvI5OFRscpO7Y2hzeLuHBgDnScNK7FP96b6ug3px4aZJjhq6U\n" +
            "J4DNwDeUdarS/6z7QhH28oVzQQ+jI5P7jHEp5aFcZxPImEjeLsKHs2GdN8iVVwKU\n" +
            "DyjXQKWpaOrpiFk8SfVkVYj+MUDSIXtxbZRSdhAz+lJm1PFTu3GlBlW4Uh8+mwGl\n" +
            "+e+glu4L0AxzAOlhhuHikGRAvSNHY5aBgCmPsYRs6kx3B9bZjoY6kS5XIH8GQfKX\n" +
            "wKLoBDuU02LAeM+BWKjR7hyUWnNKr6bt2IH+AnnSpP3kTBv7Q+yGIMRpDCzLWYbp\n" +
            "5RQf0+PyZlzvbLc9zlsLRsQpRZ6utDANQnnXdyg/DEaL4up7mdJzVTXGc0it9xvp\n" +
            "t93GrFf7klwUETcOnP+hoBL2w5+FcAHd73CoZ8GQIi6CtBJi/85EQ3IfyEXBF5l/\n" +
            "NVtZt14uS+u4XNQFKiMKQnRyZ8I4iz/Ybd8FLvtmiL6kI6Poe92FRFRwLSpqZrYi\n" +
            "WLcuVkFy7wzPOvS+gTbSFTP0xYIidqmjWBrabjxM1a2XUglcFL1lRGMt5pvHsDrz\n" +
            "dDmWZZp2d+Z2AZwL1GdUA8LPaNp+rbkQeeOlu2FGFgBvrt9cmRG7DJWLGf/wLuuC\n" +
            "hSGLOw6ZwVaPqNAuz7esnIUSeA0QdN1gssRhzGnuiDFoN9uirefhuZH6hfFNRRgo\n" +
            "Bm+6cpuzybZYsPE3/+PIEjyTAhJZtGUIuDiqwyLw4rsoK1hKMEkWfe42U6eqCFea\n" +
            "xPIvulUSkjcNa1Xg8SU6uNamlIz4RwAgS/cvmlmyZuzTiaYughl9xZ1/cHCCwFts\n" +
            "Aj8kBuj3s/4GgVx7Q4YV0hUJ9OKRahiTGrOg53Hm7akkMIljqUVM9NNjYBZR/l9N\n" +
            "Bk/KeLspTawHp3XaUdu8HVoDIJn4y2nEMcbhC30I2KEMpZR7cIrWO8lxKg6REJp8\n" +
            "FM+PpkR8VS9nPuU7IFCnxdnlH3XUGsR7tIOhpxhNujxOEH686mgCigR8m1GVD69W\n" +
            "5vE+mDmPGaZiPuNUIu7pCVA7nihPeH+Hyn9L8jJQkJXrwm4Y2bo6L8hT0Wm2o1C6\n" +
            "WoDadMMrioP9hWwacXmfWp48MCEAAAIBAM4gEFhRnSmxl7CMXOI7PWRtp7T2spp4\n" +
            "lPSJIlo7+DE6B+8AGXskGAnJOc8KBNQominGFeoQ6QaEOxajo3wsGgddHjlAAoFX\n" +
            "JorUImC8Tbb4XGXGRI88IF0jgOvvRpHeuL952IjLUzNnXaETwCwZw3Q0iMMPTAHi\n" +
            "VOQLJyFmwkfKVKpMN3/IsoHVCq3oMl2vg9/FYzO6U+s6g9PMC9eV7jx4fh+6hf/9\n" +
            "mkC4QS5cBUWqI1JnwzuOEBSSsDFhN765yB6jiROezMgnkJqZxb6W2zLtDBEYbkFS\n" +
            "keYRfbRRs3QCqxs30rxCFYuzg5kE9/7S0A5nUvI1pCgfR1Fri/ah/UTBi4c9hTPA\n" +
            "2UpyRzQ23NcruAacTIYJpLctFVU1rgabGFzDlWeEKuY2kR/egt9Wykr3ACk26NdD\n" +
            "IvmuxBJg46PH4M6vmthGE4ZRewmFzAFjbJC0LHKSgne1XWli58ELyiFd3pRp4sYF\n" +
            "Zi4iWqYv2KGcRNxtgDoGstD1aEdOpribKcDdWIAba/zuTR9T36+L5gSmGf30VyX9\n" +
            "ZbdG+Up96p913WktXo4Li+C2k70Lu49w4xW9CIO4pCOEe5wzp3MSbonkKdg//u93\n" +
            "hEtYPUaBU9UYUnAWLfu0VKh2TuDsLbN7gEziI5vPkRyyisT7w7s1VSMwpdhtRtZz\n" +
            "aaPsOaGBwXuXAAACAQDCQ6tPD3Dk2H/Q2oychhoN2NJ/K7NP0On+doZ8ACAhciHW\n" +
            "KzbvsmVps3yZfhRRBa23c3oyeeKYFRsKW/b4a8z8QVvI8rmgoAQsw6R/uHdLvmiI\n" +
            "1i8DiIYwr9SI/7e3O9Up5l7G5rzAhp3w2QvWDmC7h48R1gj1P0jbye6EDvsis14v\n" +
            "s34VoKBJyr9NdlOwXtTRdYeRjJpYYVuSzZuZNvihyuJpz7Zd81L6imstcNfC3Tu7\n" +
            "FVDEg9ER0VXkUrh2IHFZ+je6cTZwdoj/ynetti0u41KPevQr3lIQbhQvkXuTjkwE\n" +
            "zpMPdU9PiMrTURh+C7aFCzH6z6/my6XjvJOZLbvLRGEhHMTDPFCsmPmlYGSpbryx\n" +
            "T626I5rtcmFnCEJ2jv2mvTqV79i0OsFUHyi61krV07HO9C7+6Bm8r7zxGVNlFMjX\n" +
            "I+Gs4XF4fkH0b8dvudRpNVQ5+ze3scBL3gCJNGEhmFHmKdosQ2eFwJi17Y6Cx2Tp\n" +
            "Epj1gMDlsBVnEVnV1Mz9tnpZ3OuTaCyAyrbA0XrmfgmFaqIOdcqXTHiE6aaHRDlw\n" +
            "mkVbYyel2WKmtRwi9k9Fy0CdJdA6ATY2QBK/MaayTjP+d0By/4sGPsfYn8Cu5I8l\n" +
            "cGvvQnuPwnnT2kF9qONLcY5otChtJprFga5evBxU6HX+J+TKy75JabcFv1V8UQAA\n" +
            "AgBM3f5IfW1XTRP4EGO18lt1DwdRhy84UdsQaWm/pnAhojOqNMAB2R5OL3bJ+nit\n" +
            "9792p54MgFuX94c8RL34fryeD/zWudwxVo+upcs7rzW+1xG6uYa581qVhfJEOHA8\n" +
            "a4zk7PzrHKW8cmOK5HYBDSXUkGtFRxkqirJeOSGAx6YXhpVuvZfPACYPrl8wjeg7\n" +
            "JWJ2O2rDes2pauK5aIGvkc6CarrPTTWzDbw9M1EzmVzcr/R2GTdDBPD4sQ1AAHto\n" +
            "Io4cOGfdtw0pFrmi5Qu+TSgt7xY4dK+IXTHtUz4FY1OpPNEWBhdbYNGVWDWwQj6z\n" +
            "LibcD5tpfVKzNNczqN5RG9jVu4Jh0vbRaAUW6E4BaWZZ2qh/m5DxAjeewjEyWCFK\n" +
            "2yqD8puzikGTquWBf87azdPbYK0qo5tnvBFhLOee2+mhC+++yWIZT7z/XIWCM2i6\n" +
            "K4jy2qInjrHBamXtYOep776OTY3fvgoYqYBHrT2+tbHIHhBxcHdkxS8qwkfzkg40\n" +
            "5WYmVed7rWvG6xu6XJIWnn7HXVGKogUdPOPyv+qHz+TcqVCwVRVEa0eTX9gaBztr\n" +
            "ttGrDrR3676T2xwsWjeZlSpL9oF1ZH8faxZPUHoT8z9Zhgl0dbOt/pPXZiTRM8VS\n" +
            "erB/l04ZPmqU7zzGXFgpRGaXsOEO9TRpiw3+sragQN/ixg==\n" +
            "Private-MAC: 5405ff514dd17380c68d08f371a9497e827a1054\n";

    final static String ppk2048 = "PuTTY-User-Key-File-2: ssh-rsa\n" +
            "Encryption: none\n" +
            "Comment: \n" +
            "Public-Lines: 6\n" +
            "AAAAB3NzaC1yc2EAAAADAQABAAABAQC0ITaAE49ievGiREUNxjccle9zJEZkNdkE\n" +
            "2Nnkl0zxlGVwShwRIjtarM0uKiUQAFD1OhkdSA/1FhZKRumIUWD+2Fkj23EEvox0\n" +
            "bTZyPzvQJERchdpvZKJyfxZgnPL6ygY6UQj8oNBhxnuwm9lL11cSJWS+4qJigT7g\n" +
            "59eEhDyBaZ/HoijtDGvfPmJlhdNcq0MlC6ALy7XXpOd4RS2oo8m/TRpLFvoSnAQ/\n" +
            "sr1wv9u7sTZh5C5RAjPN8LWBu7GuodqZ8PhlyT3oT+qbjpA/2e18vQta1ELROBKk\n" +
            "qsLnsN4fjH69eYSZ8h5R07tfvQxTKRwCWKziqMjP4dF9Lz+gVcy1\n" +
            "Private-Lines: 14\n" +
            "AAABAQCqLWasAc7JH5YB07XZmZafrxeWFINcUXNCnQzeZgMPiT98osd5eHnS5MbE\n" +
            "ApUZVPMne0gW3eoVhlRwwCYJ37hfjE5LDhrsfIl9xWBW916u+lSLhPolm1HOEjs1\n" +
            "85GrVgokNkLjSZsVhMt+wv68JCnivuk7XipEHg8ltGNskvIG4AjW97uBqewyvyeG\n" +
            "wsPYyBtiifRxJQ1th5hlLPh+jOBsyz91uC+ZeEW2pil2ftI7XrbKVbA95SRh4W8R\n" +
            "tNBjqUpI+M2mJQ7nwh2gxd/GdNxKyvTUyCAfJo+DzAG+XRGW1Px7ibFw38jiT+CP\n" +
            "tKTjCZRFMPUvmoH3MR1hzjqjqpuBAAAAgQDj4/2h35V/aAEYvQfkwF4k6rWOY15+\n" +
            "gEV+gbfjWlYGxkH6U0AvMQv3c6EAvJNQsKip3/fqOHgdd37CcGVW+NQTucHlxz8K\n" +
            "e4cYs0Dy8g4gcNhy2M99MOy9TuMsC0/mrTQUP0Vewwo7FASWF23sbhZsBM//BC8W\n" +
            "m3LM843RwCbvXQAAAIEAylkY1TU721y22mVA2C+o6ADs55ZtMGJqjI0DjOiWCgxt\n" +
            "j6pXRmJQ05hFZy4pO4AOYMZ5IW7MdqmCu2+GVytA6PxA6C+OGYF0Eh1YJbIh/Qrv\n" +
            "07NMrYQVwQY2+FAJpLAwWJAjlrRRlANgGBHkbppf8RuQFB/euToHCZ6R6goJdTkA\n" +
            "AACAOn0n+B0Lums/2FFmBRak2niTRONt6GMWhtK4e42MnKN3VxMGshAB4SdDAQOY\n" +
            "4Qk66RYmniuhaC3sLwxtXsEKoVnMp9EXVoTPEd+BQCVBOJzZDVtAaejO9bqrvRL8\n" +
            "kmknsX54RBXxrOVvNTofHLiRojncZnRSrM3BR+Xjo0b0+mE=\n" +
            "Private-MAC: c9c10df8a1e3546eedcc08608efd5338de5df723\n";

    final static String ppk4096 = "PuTTY-User-Key-File-2: ssh-rsa\n" +
            "Encryption: none\n" +
            "Comment: \n" +
            "Public-Lines: 12\n" +
            "AAAAB3NzaC1yc2EAAAADAQABAAACAQDMlwE5YNobWP8R47Ms41hnQnATKfJblTxW\n" +
            "k/6nf+5IOknCNFBMQUOnToCmvcVRPzepr3nRFGm/gvo5SjsKdE4b0b9eT7xOGAYM\n" +
            "9y18qO3flt6hARasK8NoivbT8Cm1f0Zj02eLBaiFpFYZOuBZdpluKiYH0wHuSPeq\n" +
            "K3Q3/arsnQj1C0X+h5f4Nm0IYIHRkNsnvZrJf+MlHtcwS+BPXpAK9tkICcP1MJ2x\n" +
            "UvTKh+TgWQJQ8EUq0OUkTBUBdmG+J6O+sdB0V6r06IpcXZUNed02F+bzP/DVUE1b\n" +
            "mJZTx0ynZhKyP6NeXlwuZ3fUZhiwwqMRvCQuq1p8/itG9Vz+eY652KIIrCoVsyH1\n" +
            "gIIRert3ADX5UySMdPcgBoDWYlfyj/fS+dR2o1lIwQXLcl9uL8ZELteSq/sLmapA\n" +
            "YJbIis3r9aJnNSVaQSKn8p20tCWNnazAcSK0RTN2h5r0/r7WfvXafFIMt6VZUxPn\n" +
            "dpFCJtxhgCrszosy87eL92NCoZvdQMOddpV3op04CDccZy0LEAt7o9dXoNNaeYlx\n" +
            "czaUTV/JcuAnk9G0u3xUpTh0AOQauuxn8Dv6yyVLvXNJANp89zAhUukEwdhqOvXD\n" +
            "U5qLLgY0Kf3v+ySj6HUWNBoms6ijF1txT3RDmJdCiVfuZ1nic9tsyp0A77S1oEEQ\n" +
            "QD7Rgmi4rQ==\n" +
            "Private-Lines: 28\n" +
            "AAACABi+/xfonhkGt7t7NjXsvcmnoJTA0x6+u1ChkADEmZbE7hz+ZOQEVOGMvkTs\n" +
            "2UwNgHcW0X43oN7YQdniH6gRD02QHjyTGmy7vSeeUjMs37DWt9Dzp8FlfbpMbLSP\n" +
            "7QuV/HagoHqRUaPwj7V3iKFplf9cO8Ngg3BGBSbhIKqRFTaPfADfvzSdRAVy19dW\n" +
            "jP1DLy7sYSeUP25C/7ZIxzXycyvQVcoCHGCw47IKHa/NpiJ4wa32kfcu0ziDt1q4\n" +
            "7fOpKcYsDdG0tOnwoqOvchLyNY6Qb4/moQO8Nc8pcq1pgt0QnJxQ1Dra4P1/6F+Z\n" +
            "hc0DjePcROgcM9LAj42Cqh/hpiCfCiLJiDts+HhQppgA4fOMy5d/wrG0nuqKfhIv\n" +
            "BsX9nJDj4eHU4eNBAoraUfNLDIq0GHYDcm+jlhqO1SHxymjIhDqS6Cz/FWf07L1Q\n" +
            "5DQ/+xHysVHCcavQk4jA7JwbZrRWo5qyKrdLoWRPFUX5w5ocLnmj0Zx8VOl6a+8M\n" +
            "Q+ehLSZXFoCbao3nES/oEkKH0RFNQsDMJb0uiKQv4b/+6bywtYIFc0eqvEqd1GSF\n" +
            "x3exCdHNhLRycaCgGSh+IdPCRrMj0N7/9pGZmbjfcZ7uKlFwqETVmy1H67NTXUCW\n" +
            "NukVfsqTRewpqjFFeaxW5GEYwEeA34MbIChfdw4/KRr5XDhFAAABAQD3c9w0rWAQ\n" +
            "rjVF1WTeD89Mf+Fnf7NvRaHAaD1EJxfimgqCD5juCIa5WSplzEBpPSG/rpl3HYVz\n" +
            "CZ98rdJSS/bmJieojefvjlz1nuuPlApg2ctCfEZYOFnNP6yt0w88GLp3aMTfIsTf\n" +
            "Z893GZnMFzMMLItLcZBTSmQLiqpyU6lWE+Tr4QOcQeCF8XqHGrLWbwACuKocmCW/\n" +
            "4nI+6gZ4SfucLXKwFgcuhSaXo0XM6HiSgZHb5wEyjS2Boad6vX8t4YdjZbCcnGVm\n" +
            "9TEm0/ow41Cl44SJUU6pLlo4UnSmR7aLmTK4iEG3fIMdEmmy4VX3MJ8fqXuVJwLE\n" +
            "RLzqEjCgIcQzAAABAQDTqB/A3CyJfeHYFO7Et6edAOklejxqRW4UuuOu55v7FOj5\n" +
            "X/yW72rWbndcci+mDXQvDL6P9EG3vF1twPS0konHqVxqj6Jlp1AtUWND2FzVTypY\n" +
            "0X7z4Mif5V0p5bS5Qx6/pBg37XXbisSANSDxFVdH0/OSTYXi4EKmh0LjU5Ls0zIw\n" +
            "MB6TYetuR1hEcCxuVESnOMUgjXMsoIwGR/jeKynle45UwTqUv/oWRQvFeIi5wlwn\n" +
            "82GtUzLxhAo/BbXc3ODWjIGfKSxBJdsn0ZEXtPAk4CTqxM3VF4s3aOFAhHBDSyOv\n" +
            "nHvWXwVRwmhtyXKEkTfAO6K4ptcS57LTNT8ta6+fAAABAQC9dPiPexqC35vWtWQd\n" +
            "Zvm8DVCVscd7IPDn952FUsf2svoQ9MWodpD1craKGadSRsFCTVeYyHzS3Sg8HwKC\n" +
            "NNoanAxpY4IqEPfuaLZZuKQsj3PsVj5rXdSEbmwCR7EhI9oDUDNcSLufR5A5DMpz\n" +
            "wY4EJmg8uC2nO/O9Rzr516pIfDGsNwsdSKGWLlhgRzJxWl7M+cJjJfRlf6XruhLI\n" +
            "WDDIq/jMHb5cLNjXdWTt3jyRQkm3HI6r5C3vc4mdInBm3tNUE+KKBtChegpgDgqg\n" +
            "hZ41/hnd1e+3on3tvrE7arM3t4IHt7grwS/i1vdukV8ilYkTYHMG/Ls+6pUr+Swy\n" +
            "z15x\n" +
            "Private-MAC: a11331fa8b59cfb2be1c8e9f67ead34ac848d514\n";

    final static String ppk1024_passphrase = "PuTTY-User-Key-File-2: ssh-rsa\n" +
            "Encryption: aes256-cbc\n" +
            "Comment: rsa-key-20121215\n" +
            "Public-Lines: 4\n" +
            "AAAAB3NzaC1yc2EAAAABJQAAAIB7KdUyuvGb2ne9G9YDAjaYvX/Mq6Q6ppGjbEQo\n" +
            "bac66VUazxVpZsnAWikcdYAU7odkyt3jg7Nn1NgQS1a5mpXk/j77Ss5C9W4rymrU\n" +
            "p32cmbgB/KIV80DnOyZyOtDWDPM0M0RRXqQvAO6TsnmsNSnBa8puMLHqCtrhvvJD\n" +
            "KU+XEw==\n" +
            "Private-Lines: 8\n" +
            "4YMkPgLQJ9hOI1L1HsdOUnYi57tDy5h9DoPTHD55fhEYsn53h4WaHpxuZH8dTpbC\n" +
            "5TcV3vYTfhh+aFBY0p/FI8L1hKfABLRxhkqkkc7xMmOGlA6HejAc8oTA3VArgSeG\n" +
            "tRBuQRmBAC1Edtek/U+s8HzI2whzTw8tZoUUnT6844oc4tyCpWJUy5T8l+O3/03s\n" +
            "SceJ98DN2k+L358VY8AXgPxP6NJvHvIlwmIo+PtcMWsyZegfSHEnoXN2GN4N0ul6\n" +
            "298RzA9R+I3GSKKxsxUvWfOVibLq0dDM3+CTwcbmo4qvyM2xrRRLhObB2rVW07gL\n" +
            "7+FZpHxf44QoQQ8mVkDJNaT1faF+h/8tCp2j1Cj5yEPHMOHGTVMyaz7gqhoMw5RX\n" +
            "sfSP4ZaCGinLbouPrZN9Ue3ytwdEpmqU2MelmcZdcH6kWbLCqpWBswsxPfuhFdNt\n" +
            "oYhmT2+0DKBuBVCAM4qRdA==\n" +
            "Private-MAC: 40ccc8b9a7291ec64e5be0c99badbc8a012bf220\n";

    final static String ppk1024_umlaut_passphrase = "PuTTY-User-Key-File-2: ssh-rsa\n" +
            "Encryption: aes256-cbc\n" +
            "Comment: user@host\n" +
            "Public-Lines: 4\n" +
            "AAAAB3NzaC1yc2EAAAADAQABAAAAgQDsQv60HaW0301hX/xV3AUcutbDDAJp7KWc\n" +
            "6swL+H6jhwe3N7FK/SA4492bK5oHwU3ea3X6moLuapTMawMQbRy1kfQm99wcYc7C\n" +
            "6PJO3uouzjDatc/aByDejbo5OL9kK4Vy7qm6tw1hC0JIM+TCvItKu+t6Myl7xzv4\n" +
            "KbSHiMzulQ==\n" +
            "Private-Lines: 8\n" +
            "hPS6HYs4t8WChglZzo5G/B0ohnw2DQS19HMPllyVr9XfDyT2Xk8ZSTye84r5CtMP\n" +
            "xF4Qc0nkoStyw9p9Tm762FhkM0iGghLWeCdTyqXVlAA9l3sr0BMJ9AoMvjQBqqns\n" +
            "gjfPvmtNPFn8sfApHVOv1qSLSGOMZFm/q6KtGuR+IyTnMuZ71b/cQYYHbsAQxt09\n" +
            "96I7jDhup/4uoi/tcPYhe998wRFSSldkAtcmYGUnDWCiivlP+gZsXvOI2zs2gCxx\n" +
            "ECEwZNTR/j3G0muRUMf91iZSMBije+41j345F+ZHJ43gYXW6lxjFtI5jr9LRGWF1\n" +
            "hTeY6IlLt4EBBGNrO8Rn0oGVuQdFQAZaredlt1V5FsgcSaMgg3rlScoz0IHHD66Q\n" +
            "Hglp/IYN6Sx6OEGjh3oLGImag+Mz9/9WWGXPLhZ4MUpFAWqcTD4qPK0jYxTCM6QC\n" +
            "TybFqMeCSEKiHSOiOGf2oQ==\n" +
            "Private-MAC: 6aec23b6267edcb87b05ddef52a80894e3a246c4";

    final static String ppkdsa_passphrase = "PuTTY-User-Key-File-2: ssh-dss\n" +
            "Encryption: aes256-cbc\n" +
            "Comment: dsa-key-20140507\n" +
            "Public-Lines: 10\n" +
            "AAAAB3NzaC1kc3MAAACBAN6eo/Yh8ih26sKRAHAta/UqKesrXRS83GN7YqAxQzsP\n" +
            "2tJ00UzOqZCdBoHIXLXC07QRJ9SkXOMnILw/KuaZ3paJ6ym92FzKi3BRfpzujIdo\n" +
            "qBAEGSGOWbz2oYPDDSi0bsL84P4O8WD7ZxKhgTb4JAxlVJiW20vPfZA8Ft6xKJyd\n" +
            "AAAAFQD1pnKWpSyHzi6RcVPn16FwmGIgmwAAAIEAiFPw87HVijatNOBeuxoU5PHH\n" +
            "80kMl0TtxoI7rhB8fKO9bu7wLcT79h6xYS4Np6nHv9ajWwwVSLh8NjKgMbCXCz2j\n" +
            "qD4ajvnusS7yz7TbTumeaGqFXEEzqzG4Xe6KXkv7kd7Yg+Dnw29zucgeAvPfuJFW\n" +
            "Gtr4CWPoHSBgpTeyemEAAACBAJYvGi5gIMJQQUhIErKbtZ64V2L0zZtYkzlms03R\n" +
            "cTBFN9++xV8zUvTPAAM8imsoxZ/5JNtNjJCAD+Ghrzyav24gxYG9v/YXtd2WsYa5\n" +
            "0E/5wxcPor82SAqU2fd3IEQ5y9KHamXBuX/5KFDOTMC6cnGsutFkeo5rXQ0fI55C\n" +
            "VSTq\n" +
            "Private-Lines: 1\n" +
            "nLEIBzB8WEaMMgDz5qwlqq7eBxLPIIi9uHyjMf7NOsQ=\n" +
            "Private-MAC: b200c6d801fc8dd8f84a14afc3b94d9f9bb2df90\n";

    final static String v3_ecdsa = "PuTTY-User-Key-File-3: ecdsa-sha2-nistp256\n" +
            "Encryption: none\n" +
            "Comment: ecdsa-key-20210819\n" +
            "Public-Lines: 3\n" +
            "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBP5mbdlgVmkw\n" +
            "LzDkznoY8TXKnok/mlMkpk8FELFNSECnXNdtZ4B8+Bpqnvchhk/jY/0tUU98lFxt\n" +
            "JR0o0l8B5y0=\n" +
            "Private-Lines: 1\n" +
            "AAAAIEblmwyKaGuvc6dLgNeHsc1BuZeQORTSxBF5SBLNyjYc\n" +
            "Private-MAC: e1aed15a209f48fdaa5228640f1109a7740340764a96f97ec6023da7f92d07ea";

    final static String v3_rsa_argon2id = "PuTTY-User-Key-File-3: ssh-rsa\n" +
            "Encryption: aes256-cbc\n" +
            "Comment: rsa-key-20210926\n" +
            "Public-Lines: 6\n" +
            "AAAAB3NzaC1yc2EAAAADAQABAAABAQCBjWQHMpKAQnU3vZZF/iHn4RA867Ox+U03\n" +
            "/GOHivW0SgGIQbhKcSSWvTzYOE+GQdtX9T2KJxr76z/lB4nghkcWkpLoQW91gNBf\n" +
            "PUagMvaBxKXC8cNqaMm99uw5KpRg8SpTJWxwYPlQtzmyxav0PRFeOMSsiRsnjNuX\n" +
            "polMDSu6vmkkuKrPzvinPZbsXoZeMybcm1gn2Zq+7ik4us0icaGxRJRuF+nVqYag\n" +
            "EmO9jmQoytyqoNWzvPYEh/dh85hESwtIKXiaMOjQg52dW5BuELPGV7ZxaKRK7Znw\n" +
            "RGW6CtoGYulo0mJz5IZslDrRK/EK2bSGDbrlAcYaajROB6aBDyaJ\n" +
            "Key-Derivation: Argon2id\n" +
            "Argon2-Memory: 8192\n" +
            "Argon2-Passes: 21\n" +
            "Argon2-Parallelism: 1\n" +
            "Argon2-Salt: baf1530601433715467614d044c0e4a5\n" +
            "Private-Lines: 14\n" +
            "QAJl3mq/QJc8/of4xWbgBuE09GdgIuVhRYGAV5yC5C0dpuiJ+yF/6h7mk36s5E3Q\n" +
            "k32l+ZoWHG/kBc8s6N9rTQnIgC/eieNlN5FK3OSSoI9PBvoAtNEVWsR2T4U6ZkAG\n" +
            "FbyF3vRWq2h9Ux8flZusySqafQ2AhXP79pr13wvMziv1QbPkPFHWaR1Uvq9w0GJq\n" +
            "rfR+M6t8/6aPKhnsCTy8MiAoIcjeZmHiG/vOMIBBoWI7KtpD5IrbO4pIgzRK8m9Z\n" +
            "JqQvgWCPnddwCeiDFOZwf/Bm6g+duQYId4upB1IxSs34j21a7ZkMSExDZyV0d13S\n" +
            "G59U9pReZ7mHyIjORqeY7ssr/L9aJPPa7YCu4J5a/Bn/ARf/X5XmMnueFZ6H806M\n" +
            "ZUtHzeG2sZGoHULpwEaY1zRQs1JD5UAeaFzgDpzD4oeaD8v+FS3RdNlgj2gtWNcl\n" +
            "h8nvWD60XbylR0BdbB553xGuC8HC0482xQCCJUc8SMHZ/k2+FKTaf2m2p4dLyKkk\n" +
            "Qrw43QcmkgypUPRHKvnVs+6qUYMDHkwtPR1ZGFqHQzlHozvO9NdY/ZXTln/qfPZA\n" +
            "5w5TKvy0/GvofhISJCMocnPbkqGR6fDcKbpUjAS/RDgsCKKS5hxf6nhsYUgrXA4G\n" +
            "hXIgqGnMefLemjRG7dD/3XE8NmF6Q8mjIideEOBeP4tRCaDC2n90rZ3yChP9bsel\n" +
            "yg/TeKxj7OLk+X3ocP3yw2lsp3zOPsptSNtGI7g9VaIPGtxGaqRaIuObdLbBxCeR\n" +
            "ZgKSIuWtz8W1kT0aWuZ0aXMPagGao0ZsffmroyVpGbzW3QaI9633Krmf7EyphZoy\n" +
            "6tV3Z/GJ5aQJFeMYPOq69ktXRLAWr800822NwEStcxtQHTWbaTk7dxh8+0xwlCgI\n" +
            "Private-MAC: 582dea09758afd93a8e248abce358287d384e5ee36d21515ffcc0d42d8c5d86a\n";

    final static String v3_rsa_argon2d = "PuTTY-User-Key-File-3: ssh-rsa\n" +
            "Encryption: aes256-cbc\n" +
            "Comment: rsa-key-20210926\n" +
            "Public-Lines: 6\n" +
            "AAAAB3NzaC1yc2EAAAADAQABAAABAQCBjWQHMpKAQnU3vZZF/iHn4RA867Ox+U03\n" +
            "/GOHivW0SgGIQbhKcSSWvTzYOE+GQdtX9T2KJxr76z/lB4nghkcWkpLoQW91gNBf\n" +
            "PUagMvaBxKXC8cNqaMm99uw5KpRg8SpTJWxwYPlQtzmyxav0PRFeOMSsiRsnjNuX\n" +
            "polMDSu6vmkkuKrPzvinPZbsXoZeMybcm1gn2Zq+7ik4us0icaGxRJRuF+nVqYag\n" +
            "EmO9jmQoytyqoNWzvPYEh/dh85hESwtIKXiaMOjQg52dW5BuELPGV7ZxaKRK7Znw\n" +
            "RGW6CtoGYulo0mJz5IZslDrRK/EK2bSGDbrlAcYaajROB6aBDyaJ\n" +
            "Key-Derivation: Argon2d\n" +
            "Argon2-Memory: 2048\n" +
            "Argon2-Passes: 5\n" +
            "Argon2-Parallelism: 3\n" +
            "Argon2-Salt: 5fa1eb89e9eac0cc562c59bc648cacea\n" +
            "Private-Lines: 14\n" +
            "CCLbHvtNdkMNqOrSM+CNF874xTjDs01+UanZX7pHmIA94nAbb9ofeEHPcw7pCCWq\n" +
            "mxj7GK8BnsEQXIS1yCnRT6yCi1d68FpdXN2QvhlbWpEuzrmw4q71XpCwYpZ3KERo\n" +
            "+/o7X2Pi4qhfaS+fgBAl2VwAiHdN2KQFewj6MWJqP2/GaegKyvnZue/3e+v/Edag\n" +
            "DCbODfNhfirISUlw5U3SxqmIdrFT+2DKbpVTCLQwTeXL+fmzdYYvjOGQq6Kx7E9L\n" +
            "iWf1aLoBZCWfN5gpMxD1F1tX1nBXmFMG8aW+lOr3+BxLMUAtjRQVsmc6Lyqb1RdV\n" +
            "eyZp1W0R2+HKmwm59WUQK46HMnXdkwUqArb28VpBE61gj+KMWna9TJP6aJTF2N6m\n" +
            "0Wv8D9WCGOrOC+IqnkfkfdSLkupu6PyyhiS69IR9b6vAyDYFxhtlEx6qZpjSKLYr\n" +
            "X11I223yPAmSoO1X24RNPpo1uU4k8NfZWH0ZICY3YZ0K3PnETNGd5C38OSptQFor\n" +
            "9aY1oV/1VencX/CmGXaQHsV5UJ/SnV78+PPSv3pEeQmd2ljmSx3kTL1BX91n4/Mc\n" +
            "jNxE3kMXJ+6DD6OGGU0VbVmYBCrFDD4Mfj8yyLKOjJgEZubCLaZoI7WhDk4qZcui\n" +
            "hzPt1tshrjIN6VKubqg84BVOWmJ3MmDD76ci9d5ILeAm4zzsliuagSLa+Y6t03hs\n" +
            "PmRnFSiCv1zrqLl20PcrPEsifGeC/o1839/9E0Gywy/JDjlbucxfU9qHOntnqQJM\n" +
            "8cAjXyuzgkKC5yzk/Py3VnjWegENrfM5Zf/eXFYFzD0cIA0ou2ap+Dcln14ckGFZ\n" +
            "kir9AVgxyOiQikD8za+QjZ2rLeuzODe9mKPPKitI4npanpGcWRl+RPCG4t9poacO\n" +
            "Private-MAC: d08aebc419131c109bbf8c200848f47eafedab9286b372c3155e8dc27e6b84cd\n";

    final static String v3_rsa_argon2i = "PuTTY-User-Key-File-3: ssh-rsa\n" +
            "Encryption: aes256-cbc\n" +
            "Comment: rsa-key-20210926\n" +
            "Public-Lines: 6\n" +
            "AAAAB3NzaC1yc2EAAAADAQABAAABAQCBjWQHMpKAQnU3vZZF/iHn4RA867Ox+U03\n" +
            "/GOHivW0SgGIQbhKcSSWvTzYOE+GQdtX9T2KJxr76z/lB4nghkcWkpLoQW91gNBf\n" +
            "PUagMvaBxKXC8cNqaMm99uw5KpRg8SpTJWxwYPlQtzmyxav0PRFeOMSsiRsnjNuX\n" +
            "polMDSu6vmkkuKrPzvinPZbsXoZeMybcm1gn2Zq+7ik4us0icaGxRJRuF+nVqYag\n" +
            "EmO9jmQoytyqoNWzvPYEh/dh85hESwtIKXiaMOjQg52dW5BuELPGV7ZxaKRK7Znw\n" +
            "RGW6CtoGYulo0mJz5IZslDrRK/EK2bSGDbrlAcYaajROB6aBDyaJ\n" +
            "Key-Derivation: Argon2i\n" +
            "Argon2-Memory: 1024\n" +
            "Argon2-Passes: 5\n" +
            "Argon2-Parallelism: 2\n" +
            "Argon2-Salt: 2845c351de77c5aa9604e407ca830136\n" +
            "Private-Lines: 14\n" +
            "Ws3CZMJ0xYa/W6s0YZqn4j8ihXK81lw88iuXrmzWu+L88+RVGTBGvOvmE0oqLsMw\n" +
            "YPIi7/eOaik1jZ+dnnD/PeJbVOqch7z2fSK1cVXMyNggPvFBQVjtxrFRhvGtIC0R\n" +
            "5py8Z7Cfi0W9N/xyjHIvNrGwuvUQpBKeK1C/zYweQJF/clBSovnV/sGGRbtEd+jk\n" +
            "rY8svRKSvX0HY0P4xftwH+E40XZhUdG2JetleCNIw0ohShuCSiO1fauxI3Az/i2J\n" +
            "Ef3pRfMLCE91QW4/3nY2ofK6yyufNhyFSjqIaDkQUNBi4EYG1W2/29mK9zLpfa+Z\n" +
            "eiujzOZJfI8QPar7gTp2sdrq7ND2YUniatwqpq9+vefTkWvMEhwuNAGvfRWgJ2qq\n" +
            "IbB/EWtvNj8vA3z3M2j0ksMRvJSGpU1n8MKVdWe5PSjvpMiCaqtOTtrP3iqS+bwJ\n" +
            "WjhV+JVod5RE0fCXnBcCkE8XdSu20m04aRIVHJvnIaKH7vZXThDdG9AhpSrUcvWM\n" +
            "OVD5q0L9W9wcVQzN7XtQhTEjm3zja+tOo0gYn0Z/497kkxdL/g/su5kpPQsbbsLF\n" +
            "0ROS5U2GZX0Le+QVg6hGIfqskBoCQp+ErTXFzIu+0//MoaZSACtW48ljeIpDj0fG\n" +
            "v2Fhc9tbpTJKvQh6wlm9gkMBSV+XcRWUMh5zBPecmR6/v9O4/MCsOse89MNs4LxL\n" +
            "sLRUABdjziKnjomq/1FlozlGGfF+v+VLhjjc1xq5ms+BEqkXUsWoJl8NNST6NqkN\n" +
            "2T4nFzZA6b+RwFJFqYHF+BvgkQ5j0hEbXo1qlqKIf3Vk+/rouPkLyUIiHxZxdX4m\n" +
            "P/LtnH79FPDQFbFl6826Ui1TPISAf3pTwKFI43HgKRrya3F5GPeQphsZHlu155JO\n" +
            "Private-MAC: 1be8357d497fd4d641ce50a142c5a91ef3b0279355d2996e0c1f13e376394301\n";

    @Test
    public void test2048() throws Exception {
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new StringReader(ppk2048));
        assertNotNull(key.getPrivate());
        assertNotNull(key.getPublic());
    }

    @Test
    public void test4096() throws Exception {
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new StringReader(ppk4096));
        assertNotNull(key.getPrivate());
        assertNotNull(key.getPublic());
    }

    @Test
    public void test8192() throws Exception {
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new StringReader(ppk8192));
        assertNotNull(key.getPrivate());
        assertNotNull(key.getPublic());
    }

    @Test
    public void testEd25519() throws Exception {
        // Generated with
        //   puttygen src/test/resources/keytypes/test_ed25519 -O private \
        //     -o src/test/resources/keytypes/test_ed25519_puttygen.ppk
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new File("src/test/resources/keytypes/test_ed25519_puttygen.ppk"));
        assertNotNull(key.getPrivate());
        assertNotNull(key.getPublic());

        OpenSSHKeyV1KeyFile referenceKey = new OpenSSHKeyV1KeyFile();
        referenceKey.init(new File("src/test/resources/keytypes/test_ed25519"));
        assertEquals(key.getPrivate(), referenceKey.getPrivate());
        assertEquals(key.getPublic(), referenceKey.getPublic());
    }

    @Test
    public void testEd25519Encrypted() throws Exception {
        // Generated with
        //   puttygen src/test/resources/keytypes/test_ed25519 -O private \
        //     -o src/test/resources/keytypes/test_ed25519_puttygen_protected.ppk \
        //     --new-passphrase <(echo 123456)
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new File("src/test/resources/keytypes/test_ed25519_puttygen_protected.ppk"),
                new UnitTestPasswordFinder("123456"));
        assertNotNull(key.getPrivate());
        assertNotNull(key.getPublic());

        OpenSSHKeyV1KeyFile referenceKey = new OpenSSHKeyV1KeyFile();
        referenceKey.init(new File("src/test/resources/keytypes/test_ed25519"));
        assertEquals(key.getPrivate(), referenceKey.getPrivate());
        assertEquals(key.getPublic(), referenceKey.getPublic());
    }

    @Test
    public void testEcDsa256() throws Exception {
        // Generated with
        //   puttygen src/test/resources/keytypes/test_ecdsa_nistp256 -O private \
        //     -o src/test/resources/keytypes/test_ecdsa_nistp256_puttygen.ppk
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new File("src/test/resources/keytypes/test_ecdsa_nistp256_puttygen.ppk"));
        assertNotNull(key.getPrivate());
        assertNotNull(key.getPublic());

        PKCS8KeyFile referenceKey = new PKCS8KeyFile();
        referenceKey.init(new File("src/test/resources/keytypes/test_ecdsa_nistp256"));
        assertEquals(key.getPublic(), referenceKey.getPublic());
    }

    @Test
    public void testEcDsa384() throws Exception {
        // Generated with
        //   puttygen src/test/resources/keytypes/test_ecdsa_nistp384_2 -O private \
        //     -o src/test/resources/keytypes/test_ecdsa_nistp384_2_puttygen.ppk
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new File("src/test/resources/keytypes/test_ecdsa_nistp384_2_puttygen.ppk"));
        assertNotNull(key.getPrivate());
        assertNotNull(key.getPublic());

        OpenSSHKeyV1KeyFile referenceKey = new OpenSSHKeyV1KeyFile();
        referenceKey.init(new File("src/test/resources/keytypes/test_ecdsa_nistp384_2"));
        assertEquals(key.getPrivate(), referenceKey.getPrivate());
        assertEquals(key.getPublic(), referenceKey.getPublic());
    }

    @Test
    public void testEcDsa521() throws Exception {
        // Generated with
        //   puttygen src/test/resources/keytypes/test_ecdsa_nistp521_2 -O private \
        //     -o src/test/resources/keytypes/test_ecdsa_nistp521_2_puttygen.ppk
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new File("src/test/resources/keytypes/test_ecdsa_nistp521_2_puttygen.ppk"));
        assertNotNull(key.getPrivate());
        assertNotNull(key.getPublic());

        OpenSSHKeyV1KeyFile referenceKey = new OpenSSHKeyV1KeyFile();
        referenceKey.init(new File("src/test/resources/keytypes/test_ecdsa_nistp521_2"));
        assertEquals(key.getPrivate(), referenceKey.getPrivate());
        assertEquals(key.getPublic(), referenceKey.getPublic());
    }

    @Test
    public void testV3KeyArgon2id() throws Exception {
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new StringReader(v3_ecdsa));
        assertNotNull(key.getPrivate());
        assertNotNull(key.getPublic());
    }

    @Test
    public void testRSAv3EncryptedKeyArgon2id() throws Exception {
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new StringReader(v3_rsa_argon2id), new UnitTestPasswordFinder("changeit"));
        assertNotNull(key.getPrivate());
        assertNotNull(key.getPublic());
        OpenSSHKeyV1KeyFile referenceKey = new OpenSSHKeyV1KeyFile();
        referenceKey.init(new File("src/test/resources/keytypes/test_rsa_putty_priv.openssh2"));
        RSAPrivateKey loadedPrivate = (RSAPrivateKey) key.getPrivate();
        RSAPrivateKey referencePrivate = (RSAPrivateKey) referenceKey.getPrivate();
        assertEquals(referencePrivate.getPrivateExponent(), loadedPrivate.getPrivateExponent());
        assertEquals(referencePrivate.getModulus(), loadedPrivate.getModulus());
        assertEquals(referencePrivate.getModulus(), ((RSAPublicKey) key.getPublic()).getModulus());
    }

    @Test
    public void testRSAv3EncryptedKeyArgon2d() throws Exception {
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new StringReader(v3_rsa_argon2d), new UnitTestPasswordFinder("changeit"));
        assertNotNull(key.getPrivate());
        assertNotNull(key.getPublic());
        assertEquals(3, key.getKeyFileVersion());

        OpenSSHKeyV1KeyFile referenceKey = new OpenSSHKeyV1KeyFile();
        referenceKey.init(new File("src/test/resources/keytypes/test_rsa_putty_priv.openssh2"));
        RSAPrivateKey loadedPrivate = (RSAPrivateKey) key.getPrivate();
        RSAPrivateKey referencePrivate = (RSAPrivateKey) referenceKey.getPrivate();
        assertEquals(referencePrivate.getPrivateExponent(), loadedPrivate.getPrivateExponent());
        assertEquals(referencePrivate.getModulus(), loadedPrivate.getModulus());
        assertEquals(referencePrivate.getModulus(), ((RSAPublicKey) key.getPublic()).getModulus());
    }

    @Test
    public void testRSAv3EncryptedKeyArgon2i() throws Exception {
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new StringReader(v3_rsa_argon2i), new UnitTestPasswordFinder("changeit"));
        assertNotNull(key.getPrivate());
        assertNotNull(key.getPublic());
        OpenSSHKeyV1KeyFile referenceKey = new OpenSSHKeyV1KeyFile();
        referenceKey.init(new File("src/test/resources/keytypes/test_rsa_putty_priv.openssh2"));
        RSAPrivateKey loadedPrivate = (RSAPrivateKey) key.getPrivate();
        RSAPrivateKey referencePrivate = (RSAPrivateKey) referenceKey.getPrivate();
        assertEquals(referencePrivate.getPrivateExponent(), loadedPrivate.getPrivateExponent());
        assertEquals(referencePrivate.getModulus(), loadedPrivate.getModulus());
        assertEquals(referencePrivate.getModulus(), ((RSAPublicKey) key.getPublic()).getModulus());
    }

    @Test
    public void testCorrectPassphraseRsa() throws Exception {
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new StringReader(ppk1024_passphrase), new UnitTestPasswordFinder("123456"));
        // Install JCE Unlimited Strength Jurisdiction Policy Files if we get java.security.InvalidKeyException: Illegal key size
        assertNotNull(key.getPrivate());
        assertNotNull(key.getPublic());
    }

    @Test
    public void testCorrectPassphraseUmlautRsa() throws Exception {
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new StringReader(ppk1024_umlaut_passphrase), new UnitTestPasswordFinder("äöü"));
        // Install JCE Unlimited Strength Jurisdiction Policy Files if we get java.security.InvalidKeyException: Illegal key size
        assertNotNull(key.getPrivate());
        assertNotNull(key.getPublic());
    }

    @Test
    public void testWrongPassphraseRsa() throws Exception {
        assertThrows(IOException.class, () -> {
            PuTTYKeyFile key = new PuTTYKeyFile();
            key.init(new StringReader(ppk1024_passphrase),
                    new UnitTestPasswordFinder("egfsdgdfgsdfsdfasfs523534dgdsgdfa"));
            assertNotNull(key.getPublic());
            assertNull(key.getPrivate());
        });
    }

    @Test
    public void testCorrectPassphraseDsa() throws Exception {
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new StringReader(ppkdsa_passphrase), new UnitTestPasswordFinder("secret"));
        // Install JCE Unlimited Strength Jurisdiction Policy Files if we get java.security.InvalidKeyException: Illegal key size
        assertNotNull(key.getPrivate());
        assertNotNull(key.getPublic());
    }

    @Test
    public void testWrongPassphraseDsa() throws Exception {
        assertThrows(IOException.class, () -> {
            PuTTYKeyFile key = new PuTTYKeyFile();
            key.init(new StringReader(ppkdsa_passphrase),
                    new UnitTestPasswordFinder("egfsdgdfgsdfsdfasfs523534dgdsgdfa"));
            assertNotNull(key.getPublic());
            assertNull(key.getPrivate());
        });
    }

    @Test
    public void corruptedPublicLines() throws Exception {
        assertThrows(IOException.class, () -> {
            PuTTYKeyFile key = new PuTTYKeyFile();
            key.init(new StringReader(corruptBase64InPuttyKey(ppk2048, "Public-Lines: ")));
            key.getPublic();
        });
    }

    @Test
    public void corruptedPrivateLines() throws Exception {
        assertThrows(IOException.class, () -> {
            PuTTYKeyFile key = new PuTTYKeyFile();
            key.init(new StringReader(corruptBase64InPuttyKey(ppk2048, "Private-Lines: ")));
            key.getPublic();
        });
    }

    private String corruptBase64InPuttyKey(
            @SuppressWarnings("SameParameterValue") String source,
            String sectionPrefix
    ) throws IOException {
        try (var reader = new BufferedReader(new StringReader(source))) {
            StringBuilder result = new StringBuilder();
            while (true) {
                String line = reader.readLine();
                if (line == null) {
                    break;
                } else if (line.startsWith(sectionPrefix)) {
                    int base64LineCount = Integer.parseInt(line.substring(sectionPrefix.length()));
                    StringBuilder base64 = new StringBuilder();
                    for (int i = 0; i < base64LineCount; ++i) {
                        base64.append(Objects.requireNonNull(reader.readLine()));
                    }
                    String corruptedBase64 = CorruptBase64.corruptBase64(base64.toString());

                    // 64 is the length of base64 lines in PuTTY keys generated by puttygen.
                    // It's not clear if it's some standard or not.
                    // It doesn't match the MIME Base64 standard.
                    int chunkSize = 64;

                    result.append(sectionPrefix);
                    result.append((corruptedBase64.length() + chunkSize - 1) / chunkSize);
                    result.append('\n');
                    for (int offset = 0; offset < corruptedBase64.length(); offset += chunkSize) {
                        result.append(corruptedBase64, offset, min(corruptedBase64.length(), offset + chunkSize));
                        result.append('\n');
                    }
                } else {
                    result.append(line);
                    result.append('\n');
                }
            }
            return result.toString();
        }
    }
}
