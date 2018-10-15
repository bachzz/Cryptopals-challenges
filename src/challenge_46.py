### EXPLAIN!!

## plaintext P is within the bounds [0, N] - LB(lower bound) = 0, UB(uppder bound) = N
## iterate this algorithm log2(N) times to find P from original ciphertext C
##		C' = ((2^e mod N) * C) mod N
##		if (oracle.check_parity(C') == ODD):
##			LB = (LB + UB) / 2
##      else:
##			UB = (LB + UB) / 2
## => The final upper bound is the plaintext we need to find

from decimal import *
from math import ceil, log
import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *

class Oracle(RSA):
	def check_parity(self, ct_int):
		plaintext = self.decrypt(ct_int)
		plaintext_int = int(ascii_to_hex(plaintext), 16)
		return plaintext_int % 2 == 0

def parity_oracle_attack(ciphertext, oracle):

    # Compute the encryption of 2, which will be our ciphertext multiplier
    multiplier = pow(2, oracle.e, oracle.n)

    # Initialize lower and upper bound.
    # need to use Decimal because it allows to set the precision for the floating point
    # numbers, which we will need when doing the binary search divisions.
    lower_bound = Decimal(0)
    upper_bound = Decimal(oracle.n)

    # Number of iterations: k = log2(n)
    k = int(ceil(log(oracle.n, 2)))
    print k
    # Set the precision of the floating point number to be enough
    getcontext().prec = k

    # Binary search for the correct plaintext
    for i in range(k):
        ciphertext = (ciphertext * multiplier) % oracle.n
        if not oracle.check_parity(ciphertext):
            lower_bound = (lower_bound + upper_bound) / 2
        else:
            upper_bound = (lower_bound + upper_bound) / 2
        print hex_to_ascii("%x" % int(upper_bound))

    return hex_to_ascii("%x" % int(upper_bound))

oracle = Oracle(1024)

b64 = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
text = base64_to_ascii(b64)
ct_int = oracle.encrypt(text)

pt = parity_oracle_attack(ct_int, oracle)
print pt


