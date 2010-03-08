repositories.remote << 'http://www.ibiblio.org/maven2/'

# Dependencies
SLF4J = 'org.slf4j:slf4j-api:jar:1.5.10'
SLF4J_LOG4J = 'org.slf4j:slf4j-log4j12:jar:1.5.10'
LOG4J = 'log4j:log4j:jar:1.2.15'
SSHD = transitive('org.apache.sshd:sshd-core:jar:0.3.0')
JCRAFT = 'com.jcraft:jzlib:jar:1.0.7'
BC = 'org.bouncycastle:bcprov-jdk16:jar:1.45'

desc 'SSHv2 library for Java'
define 'sshj', :version=>'0.1a', :group=>'sshj' do
    
    compile.with SLF4J, LOG4J, SLF4J_LOG4J, BC, JCRAFT

    test.with SSHD, LOG4J, SLF4J, SLF4J_LOG4J
    
    package(:jar).exclude('**/examples')
    package(:sources).exclude('**/examples')
    package(:javadoc)
    package(:zip, :classifier=>'examples').path('examples').include(_('**/examples/*.java'))
    
end
