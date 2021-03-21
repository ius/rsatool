Description
-----------
rsatool calculates RSA (p, q, n, d, e) and RSA-CRT (dP, dQ, qInv) parameters given
either two primes (p, q) or modulus and private exponent (n, d).

Resulting parameters are displayed and can optionally be written as an OpenSSL compatible DER or PEM encoded RSA private key.

Requirements
------------

* python v3.7+
* [pyasn1][1]
* [gmpy2][2]

Usage examples
--------------

Supplying modulus and private exponent, PEM output to key.pem:

    python rsatool.py -f PEM -o key.pem -n 13826123222358393307 -d 9793706120266356337

Supplying two primes, DER output to key.der:

    python rsatool.py -f DER -o key.der -p 4184799299 -q 3303891593

[1]: http://pypi.python.org/pypi/pyasn1/
[2]: http://pypi.python.org/pypi/gmpy2/
