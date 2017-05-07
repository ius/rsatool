#!/usr/bin/env python2
import base64, fractions, optparse, random
try:
    import gmpy
except ImportError as e:
    try:
        import gmpy2 as gmpy
    except ImportError:
        raise e

from pyasn1.codec.der import encoder
from pyasn1.type.univ import *

PEM_TEMPLATE = '-----BEGIN RSA PRIVATE KEY-----\n%s-----END RSA PRIVATE KEY-----\n'
DEFAULT_EXP = 65537

def factor_modulus(n, d, e):
    """
    Efficiently recover non-trivial factors of n

    See: Handbook of Applied Cryptography
    8.2.2 Security of RSA -> (i) Relation to factoring (p.287)

    http://www.cacr.math.uwaterloo.ca/hac/
    """
    t = (e * d - 1)
    s = 0

    while True:
        quotient, remainder = divmod(t, 2)

        if remainder != 0:
            break

        s += 1
        t = quotient

    found = False

    while not found:
        i = 1
        a = random.randint(1,n-1)

        while i <= s and not found:
            c1 = pow(a, pow(2, i-1, n) * t, n)
            c2 = pow(a, pow(2, i, n) * t, n)

            found = c1 != 1 and c1 != (-1 % n) and c2 == 1

            i += 1

    p = fractions.gcd(c1-1, n)
    q = n // p

    return p, q

class RSA:
    def __init__(self, p=None, q=None, n=None, d=None, e=DEFAULT_EXP):
        """
        Initialize RSA instance using primes (p, q)
        or modulus and private exponent (n, d)
        """

        self.e = e

        if p and q:
            assert gmpy.is_prime(p), 'p is not prime'
            assert gmpy.is_prime(q), 'q is not prime'

            self.p = p
            self.q = q
        elif n and d:   
            self.p, self.q = factor_modulus(n, d, e)
        else:
            raise ArgumentError('Either (p, q) or (n, d) must be provided')

        self._calc_values()

    def _calc_values(self):
        self.n = self.p * self.q

        if self.p != self.q:
            phi = (self.p - 1) * (self.q - 1)
        else:
            phi = (self.p ** 2) - self.p

        self.d = gmpy.invert(self.e, phi)

        # CRT-RSA precomputation
        self.dP = self.d % (self.p - 1)
        self.dQ = self.d % (self.q - 1)
        self.qInv = gmpy.invert(self.q, self.p)

    def to_pem(self):
        """
        Return OpenSSL-compatible PEM encoded key
        """
        return (PEM_TEMPLATE % base64.encodestring(self.to_der()).decode()).encode()

    def to_der(self):
        """
        Return parameters as OpenSSL compatible DER encoded key
        """
        seq = Sequence()

        for x in [0, self.n, self.e, self.d, self.p, self.q, self.dP, self.dQ, self.qInv]:
            seq.setComponentByPosition(len(seq), Integer(x))

        return encoder.encode(seq)

    def dump(self, verbose):
        vars = ['n', 'e', 'd', 'p', 'q']

        if verbose:
            vars += ['dP', 'dQ', 'qInv']

        for v in vars:
            self._dumpvar(v)

    def _dumpvar(self, var):
        val = getattr(self, var)

        parts = lambda s, l: '\n'.join([s[i:i+l] for i in range(0, len(s), l)])

        if len(str(val)) <= 40:
            print('%s = %d (%#x)\n' % (var, val, val))
        else:
            print('%s =' % var)
            print(parts('%x' % val, 80) + '\n')


if __name__ == '__main__':
    parser = optparse.OptionParser()

    parser.add_option('-p', dest='p', help='prime', type='int')
    parser.add_option('-q', dest='q', help='prime', type='int')
    parser.add_option('-n', dest='n', help='modulus', type='int')
    parser.add_option('-d', dest='d', help='private exponent', type='int')
    parser.add_option('-e', dest='e', help='public exponent (default: %d)' % DEFAULT_EXP, type='int', default=DEFAULT_EXP)
    parser.add_option('-o', dest='filename', help='output filename')
    parser.add_option('-f', dest='format', help='output format (DER, PEM) (default: PEM)', type='choice', choices=['DER', 'PEM'], default='PEM')
    parser.add_option('-v', dest='verbose', help='also display CRT-RSA representation', action='store_true', default=False)

    try:
        (options, args) = parser.parse_args()

        if options.p and options.q:
            print('Using (p, q) to initialise RSA instance\n')
            rsa = RSA(p=options.p, q=options.q, e=options.e)
        elif options.n and options.d:
            print('Using (n, d) to initialise RSA instance\n')
            rsa = RSA(n=options.n, d=options.d, e=options.e)
        else:
            parser.print_help()
            parser.error('Either (p, q) or (n, d) needs to be specified')

        rsa.dump(options.verbose)

        if options.filename:
            print('Saving %s as %s' % (options.format, options.filename))


            if options.format == 'PEM':
                data = rsa.to_pem()
            elif options.format == 'DER':
                data = rsa.to_der()

            fp = open(options.filename, 'wb')
            fp.write(data)
            fp.close()

    except optparse.OptionValueError as e:
        parser.print_help()
        parser.error(e.msg)
