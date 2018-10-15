### EXPLAIN! EXPLAIN! EXPLAIN!
### Diffie-Helman (basic key exchange) 

## Alice & Bob wants to exchange secret key in an open channel
## => Alice sends A to Bob, Bob sends B to A
## Alice has secret a, Bob has secret b such that, A = (g ^ a) mod p, B = (g ^ b) mod p (g, p are constants)
## => Secret key of Alice & Bob is kAB = A^b = B^a = (g ^ ab) mod p

import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *


alice = diffie_helman()
bob = diffie_helman()
alice_key = alice.public_key()
bob_key = bob.public_key()

print "Alice's secret_key:", alice.secret_key(bob_key)
print "Bob's secret_key:", bob.secret_key(alice_key)
assert alice.secret_key(bob_key) == bob.secret_key(alice_key) 
