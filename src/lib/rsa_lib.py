import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *
from Crypto.Util.number import getPrime

def find_cube_root(n):
    """Finds the cube root of n using binary search."""
    lo = 0
    hi = n

    while lo < hi:
        mid = (lo + hi) // 2
        if mid**3 < n:
            lo = mid + 1
        else:
            hi = mid

    return lo

def gcd(a, b):
    # Computes the greatest common divisor between a and b using the Euclidean algorithm.
    while b != 0:
        a, b = b, a % b

    return a


def lcm(a, b):
    # Computes the lowest common multiple between a and b using the GCD method.
    return a // gcd(a, b) * b

def inv_mod(e, n):
    # Computes the multiplicative inverse of a modulo n using the extended Euclidean algorithm.
    # d * e = 1 (mod n)		|| need to find d
    # <=> (d * e) mod n = 1 mod n

    t, r = 0, n
    new_t, new_r = 1, e

    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r

    if r > 1:
        raise Exception("e is not invertible")
    if t < 0:
        t = t + n

    return t

class RSA():
	def __init__(self, key_length):
		phi = 0
		self.e = 3

		while gcd(self.e, phi) != 1:
			p, q = getPrime(key_length // 2), getPrime(key_length // 2)
			phi = lcm(p - 1, q - 1)
			self.n = p * q
			
		self.d = inv_mod(self.e, phi)
	def encrypt(self, message):
		message_int = int(ascii_to_hex(message), 16)
		return pow(message_int, self.e, self.n)
	def decrypt(self, ct_int):
		pt_int = pow(ct_int, self.d, self.n)#[2:]
		pt_hex = "%x" % pt_int
		return hex_to_ascii(pt_hex)
