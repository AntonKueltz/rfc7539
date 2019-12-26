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
    nonce = b'thisisanonce'  # nonce is 12 bytes (DO NOT REUSE A NONCE WITH THE SAME KEY)
    message = b'Some message to be encrypted'
    additional_data = b'Some additional data'  # this will not be encrypted but will be verified for integrity

    # encryption
    ciphertext, mac = aead.encrypt_and_tag(key, nonce, message, additional_data)

    # decryption (which yields plaintext == message)
    plaintext = aead.verify_and_decrypt(key, nonce, ciphertext, mac, additional_data)


Note that all operations in this package work on bytes. You'll need to call e.g. :code:`encode()` on strings
before passing them as arguments.

.. _RFC7539: https://tools.ietf.org/html/rfc7539
