sshj - SSHv2 library for Java
==============================

To get started, have a look at one of the examples. Hopefully you will find the API pleasant to work with :)

Features of the library include:

* reading known_hosts files for host key verification
* password and publickey authentication
* command, subsystem and shell channels
* local and remote port forwarding
* scp + complete sftp version 3 implementation

Implementations for the following algorithms are included:

ciphers
  ``aes{128,192,256}-{cbc,ctr}``, ``blowfish-cbc``, ``3des-cbc``

key exchange
  ``diffie-hellman-group1-sha1``, ``diffie-hellman-group14-sha1``

signatures
  ``ssh-rsa``, ``ssh-dss`` signaures

mac
  ``hmac-md5``, ``hmac-md5-96``, ``hmac-sha1``, ``hmac-sha1-96``

compression
  ``zlib`` and ``zlib@openssh.com`` (delayed zlib)

private key files
   ``pkcs8`` encoded (what openssh uses)

If you need something that is not implemented, it shouldn't be too hard to add since (do contribute it!)


Building
--------

You will need buildr_. To see available tasks, run::

  $ buildr help:tasks

Since there is no official release yet you can use the ``package`` task to create a jar.


Runtime dependencies
--------------------

slf4j_ is required. bouncycastle_ is highly recommended and required for using some of the crypto algorithms.
jzlib_ is required for using zlib compression.


Contributing
------------

Fork away!


.. _buildr: http://buildr.apache.org/installing.html

.. _slf4j: http://www.slf4j.org/download.html

.. _bouncycastle: http://www.bouncycastle.org/java.html

.. _jzlib: http://www.jcraft.com/jzlib/