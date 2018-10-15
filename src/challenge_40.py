### EXPLAIN!

## Attack RSA based on CRT (Chinese Remainder Theorem):
'''		Let p, q be coprime. Then the system of equations:
			x = a (mod p)
			x = b (mod q)
		have a unique solution x modulo (p * q)
'''
## For RSA:
	# Attacker got CT1, CT2, CT3 with corresponding public keys N1, N2, N3:
'''
			C1 = M^3 mod N1
			C2 = M^3 mod N2
			C3 = M^3 mod N3
'''
	# => We need to find M (unique)
	# => Follow the steps in the challenge to find M

import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *


cipher1 = RSA(1024)
cipher2 = RSA(1024)
cipher3 = RSA(1024)

message = "Privacy is just a myth."

# 3 different ciphertext
ct1 = cipher1.encrypt(message)
ct2 = cipher2.encrypt(message)
ct3 = cipher3.encrypt(message)

# 3 different public keys
N1 = cipher1.n
N2 = cipher2.n
N3 = cipher3.n


m_s_1 = N2 * N3
m_s_2 = N1 * N3
m_s_3 = N2 * N1

'''result =
  (ct1 * m_s_1 * invmod(m_s_1, n_1)) +
  (ct2 * m_s_2 * invmod(m_s_2, n_2)) +
  (ct3 * m_s_3 * invmod(m_s_3, n_3)) mod N_012'''

y1 = ct1 * m_s_1 * inv_mod(m_s_1, N1)
y2 = ct2 * m_s_2 * inv_mod(m_s_2, N2)
y3 = ct3 * m_s_3 * inv_mod(m_s_3, N3)

result = (y1 + y2 + y3) % (N1 * N2 * N3)

plaintext_hex = "%x" % find_cube_root(result)
plaintext = hex_to_ascii(plaintext_hex)
print plaintext

