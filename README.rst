=======
RFC7539
=======
.. image:: https://img.shields.io/pypi/v/rfc7539.svg
    :target: https://pypi.org/project/rfc7539/
    :alt: PyPI

.. image:: https://travis-ci.org/AntonKueltz/rfc7539.svg?branch=master
    :target: https://travis-ci.org/AntonKueltz/rfc7539
    :alt: Travis

About
-----

RFC7539_ is an IETF specification for an authenticated encryption algorithm that will be
incorporated into TLSv1.3. It is comprised of a stream cipher (ChaCha20) and a MAC (Poly1305), both
written by Daniel J. Bernstein. The C implementations for both of these primitives are taken from
the NSS library (the reason being that openSSL has license incompatibilities and also requires the
openSSL headers which is more overhead than we need to implement these fairly basic primitives).
The NSS code has been slightly modified to account for the 96 bit nonce and 32 bit counter
specified in the RFC.

Installation
------------

Method 1
~~~~~~~~

.. code:: bash

    pip install rfc7539

Method 2
~~~~~~~~

.. code:: bash

    git clone https://github.com/AntonKueltz/rfc7539.git
    cd rfc7539
    python setup.py install

Usage
-----

You should use the authenticated encryption mode unless you really need to use one of the primitives
by itself:

.. code:: python

    from rfc7539 import aead
    from os import urandom

    key = urandom(32)  # key is 32 bytes
    nonce = 'thisisanonce'  # nonce is 12 bytes (DO NOT REUSE A NONCE WITH THE SAME KEY)
    message = 'Some message to be encrypted'
    additional_data = 'Some additional data'  # this will not be encrypted but will be verified for integrity

    # encryption
    ciphertext, mac = aead.encrypt_and_tag(key, nonce, message, additional_data)

    # decryption (which yields plaintext == message)
    plaintext = aead.verify_and_decrypt(key, nonce, ciphertext, mac, additional_data)

Notes on Python 2 vs 3
----------------------

In python2 encryption and decryption and tagging will return :code:`str` data while in python3 they will return
:code:`bytes` data. This is consistent with how much of the python library operates between the two versions (e.g.
see :code:`binascii.unhexlify`). This can lead to some strange behavior if e.g. you encrypt a :code:`str` value in
python3 and, after decrypting, your decrypted value does not match your original value because you got :code:`bytes`
back from the decryption. If the returned type is undesirable it is of course always possible to convert between
:code:`bytes` and :code:`str` as needed.

.. _RFC7539: https://tools.ietf.org/html/rfc7539
