### EXPLAIN!!!

### Good reference: https://www.iacr.org/archive/crypto2004/31520306/multicollisions.pdf

### WHAT TO DO?
## 		Step 1: build merkle_damgard() hash function
##		Step 2: generate collisions
##		Step 3: - Take f, g are 2 different hash functions
##					+ f(x) is hashing function with "cheap" state "\x00\x00"
##					+ g(x) is hashing function with "expensive" state "\x00\x00\x00\x00"
##				- Build h such that h(x) = f(x) || g(x)
##				- Find collision between 2 hash functions f & g

### NOTE: About generating collisions
## Consider h(x) - a hash function (I use ECB for this challenge) that we can find 
## 											 2 "colliding" messages from each hash
## Here's how calling h(x) i times can generate 2^i colliding messages
## 	  E.g: i = 2
'''
		    --- m1 ---		--- m2 ---
		h0 -- 		 -- h1 --		 -- h2 -- (...)
		    --- m1'---		--- m2'---
'''
'''
	=>	h2 = -- h(m2, h1)  =  -- -- h(m2, h(m1, h0))
			 |				  |  |
			 -- h(m2', h1)	  |	 -- h(m2, h(m1', h0))
							  -- -- h(m2', h(m1, h0))
							     |
							     -- h(m2', h(m1', h0))
'''

import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *

def merkle_damgard(m, h, nopadding=False):
    state_size = len(h)
    m = str(m)
    if not nopadding:
        m = pkcs7_padding(m)

    for block in range(len(m) / AES.block_size):
        start = block * AES.block_size
        end = start + AES.block_size
        key = pkcs7_padding(h)
        h = aes_ecb_enc(m[start:end], key)[:state_size]

    return h


def find_collision(m, h):
    lookup = {}

    hashed = merkle_damgard(m, h)
    while hashed not in lookup:
        lookup[hashed] = m
        m += 1
        hashed = merkle_damgard(m, h)

    return str(m), str(lookup[hashed]), hashed


def generate_collisions(n, start):
    h = '\x00\x00'
    collisions = []

    for i in range(n):
        prev_collisions = collisions
        s1, s2, hashed = find_collision(start, h)

        if not collisions:
            collisions = [s1, s2]
            #print collisions
        else:
            collisions = [pkcs7_padding(p) + s1 for p in prev_collisions]
            collisions += [pkcs7_padding(p) + s2 for p in prev_collisions]

        h = hashed

    return collisions


def find_collision_btwn_2_functions():
    expensive_size = 4
    expensive_state = '\x00' * expensive_size
    start = 0

    while True:
        lookup = {}
        collisions = generate_collisions(expensive_size * 4, start)
        print collisions
        print 'Generated {} collisions...'.format(len(collisions))

        for m in collisions:
            h = merkle_damgard(m, expensive_state)

            if h in lookup:
                collision = lookup[h]
                assert merkle_damgard(m, '\x00\x00') == merkle_damgard(collision, '\x00\x00')
                return 'Found collision for values {} and {}, hash = {}'.format(
                    hexlify(m), hexlify(collision), hexlify(h))
            else:
                lookup[h] = m

        start += 100000

    return 'No collisions found'

print find_collision_btwn_2_functions()