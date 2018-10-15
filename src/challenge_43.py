### NOTE: USE PYTHON3!! python2 doesn't give correct result, I'll look into it when I have time.

### EXPLAIN!

## DSA (Digital Signature Algorithm) involves 3 main parts:
##		1. Key generation:
##			- Generate a 1024-bit prime p
##			- Find a 160-bit prime divisor q of p-1
##			- Find an element g which generates the subgroup of p with q elements
##			- Choose a random private key x (0 < x < q)
##			- Compute y = g ^ x mod p
##			=> The keys are now:
##				public = (p, q, g, y)
##				private = (x)
##		2. Signing:
##			- Choose a random key 0 < k < q
##			- Compute r = g ^ k mod q
##			- Compute s = (SHA(message) + x*r) * inv_mod(k, q) mod q
##		3. Verifying:
##			- Compute w = inv_mod(s, q) 
##			- Compute u1 = w * SHA(message) mod q
##			- Compute u2 = w * r mod q
##			- Compute v = (g^u1 * y^u2 mod p) mod q
##			- Verify v == r mod q

## How to recover private key from signature's nonce?
##		- Attacker has: H(message), r, s, y (public key)
##		- Given k, private key can be calculated:
##			x = (s * k) - H(message) * inv_mod(r,q) mod q
##		- Attacker brute-forces k until get_public_key_from_private_key(x) == y
##		- if True, return x - the private key



import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *



def crack_key(dsa, r, s, message_hash, y):
	for k in range(2 ** 16):
		x = (((s * k) - message_hash) * inv_mod(r, dsa.q)) % dsa.q 
		# If the private key x corresponding to the current k generates the correct public key, return it
		if pow(dsa.g, x, dsa.p) == y:
			#print x
			return x

dsa = DSA()
m = b"Anonymous"
r, s = dsa.sign(m)
assert dsa.verify(m, r, s)
print ("Tested signing & verifying successfully!")

#message = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"
# message = '''For those that envy a MC it can be hazardous to your health
# So be friendly, a matter of life and death, just like a etch-a-sketch
# '''
message = b"For those that envy a MC it can be hazardous to your health\n" \
              b"So be friendly, a matter of life and death, just like a etch-a-sketch\n"

r = 548099063082341131477253921760299949438196259240
s = 857042759984254168557880549501802188789837994940
y = int("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4"
      "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004"
      "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed"
      "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b"
      "bb283e6633451e535c45513b2d33c99ea17", 16)
private_key = crack_key(dsa, r, s, dsa.h_sha1(message), y)
c = hex(private_key)[2:].encode()
print ("SHA-1 fingerprint:", sha1(c))
assert sha1(c) == "0954edd5e0afe5542a4adf012611a91912a3ec16"#"a0f66d38aea174c54c34460ba079064149a84333"#"0954edd5e0afe5542a4adf012611a91912a3ec16"
