sshj - SSHv2 library for Java
==============================

Building
--------

You will need `buildr  <http://buildr.apache.org/>`_. To see available tasks, run::

  $ buildr help:tasks

Since there is no official release yet you can use the ``package`` task to create a jar.

Dependencies
-------------

Required:

* slf4j

Optional:

* bouncycastle for using high-strength ciphers and for reading openssh private key files
* jzlib for using zlib compression

Contributing
-------------

Fork away!