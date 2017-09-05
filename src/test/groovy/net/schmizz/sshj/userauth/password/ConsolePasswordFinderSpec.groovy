package net.schmizz.sshj.userauth.password

import spock.lang.Specification

class ConsolePasswordFinderSpec extends Specification {

    def "should read password from console"() {
        given:
        def console = Mock(Console) {
            readPassword(*_) >> "password".toCharArray()
        }
        def cpf = new ConsolePasswordFinder(console)
        def resource = new AccountResource("test", "localhost")

        when:
        def password = cpf.reqPassword(resource)

        then:
        password == "password".toCharArray()

    }
}
