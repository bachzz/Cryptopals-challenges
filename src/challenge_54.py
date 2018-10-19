### EXPLAIN!!

## GOOD reference: https://eprint.iacr.org/2005/281.pdf

## GOAL: make a prediction about some event that hashes to some output H and after the event has passed, 
##       create a correct "prediction" that also hashes to H, thus convincing people that 
##       we knew the results of the event beforehand

## STEPS:
    # Step 1: Generate a large number of initial hash states. Say, 2^k with k = 8 (I use urandom(2) - 2 bytes for each state)
    # Step 2: Using "diamond structure", get your prediction from initial 2^k states
    #         (Get colliding messages with each 2 pair of states -> generate an intermediate hash value)
'''
              h[0,0] |-->| h[1, 0] |--> h[2, 0] |--> h[3,0]
              h[0,1] |-->|         |            |
                                   |            |
              h[0,2] |-->| h[1, 1] |-->         |
              h[0,3] |-->|                      |
              
              h[0,4] |-->| h[1, 2] |--> h[2, 1] |-->
              h[0,5] |-->|         |            |
                                   |            |
              h[0,6] |-->| h[1, 3] |-->         |
              h[0,7] |-->|

        NOTE: each "-->" corresponds to a message
'''
    # Step 3: You need to commit to some length to encode in the padding. Make sure it's long enough to accommodate 
    #         your actual message, this suffix, and a little bit of glue to join them up. 
    #         Hash this padding block using the state from step 2


import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *
from os import urandom

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

def find_collision(h1, h2):
    lookup = {}

    for _ in range(2**8):
        m = urandom(2)
        hashed = merkle_damgard(m, h1)
        lookup[hashed] = m

    m = urandom(2)
    hashed = merkle_damgard(m, h2)
    while hashed not in lookup:
        m = urandom(2)
        hashed = merkle_damgard(m, h2)

    return lookup[hashed], m, hashed


def generate_states(k):
    funnel = []
    initial_states = set()

    while len(initial_states) != 2 ** k:
        initial_states.add(urandom(2))
    states = list(initial_states)

    while len(states) != 1:
        next_states = []
        # Step 1.1: Pair them up and generate single-block collisions.
        for i in range(0, len(states), 2):
            h1, h2 = states[i], states[i+1]
            m1, m2, h = find_collision(h1, h2)

            funnel.append((h1, m1))
            funnel.append((h2, m2))
            next_states.append(h)

        states = next_states[:]
        if len(next_states) == 1:
            funnel.append((h, None))

    return funnel[::-1]


def generate_suffix(m, funnel):
    target_states = {h: i for (i, (h, _)) in enumerate(funnel) if i > len(funnel) / 2}

    glue = urandom(2)
    hashed = merkle_damgard(m + glue, '\x00\x00')
    while hashed not in target_states:
        glue = urandom(2)
        hashed = merkle_damgard(m + glue, '\x00\x00')

    m = pkcs7_padding(m + glue)
    i = target_states[hashed]
    while i != 0:
        h, a = funnel[i]
        m += pkcs7_padding(a)
        i = (i - 1) / 2

    return m


def nostradamus():
    # Step 1: Generate a large number of initial hash states. Say, 2^k with k = 8.
    funnel = generate_states(8)
    assert funnel[0][1] is None # Check that output of "diamond structure" only contain 1 state 
    
    # Step 2: You have one state. This is your prediction
    prediction = merkle_damgard('', funnel[0][0])
    print 'Prediction hash = {}'.format(hexlify(prediction))

    # Step 3: You need to commit to some length to encode in the padding. Make sure it's long enough to accommodate 
    #         your actual message, this suffix, and a little bit of glue to join them up. Hash this padding block using the state from step 2
    m = 'This message predicts every result for the coming baseball season'
    m = generate_suffix(m, funnel)

    hashed = merkle_damgard(m, '\x00\x00')
    assert hashed == prediction
    return 'Generated message {} with hash = {}'.format(repr(m), hexlify(hashed))

print nostradamus()