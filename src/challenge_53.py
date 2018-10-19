### EXPLAIN!!!

## GOAL: find x' such that H(x') = H(x) = y 

## GOOD reference (part 4.2 - long-Message Attacks with Expandable Messages): 
##          https://www.schneier.com/academic/paperfiles/paper-preimages.pdf

## Steps:
    # Step 1: Generate an expandable message of length (k, k + 2^k - 1)
        # Step 1.1: Starting from the hash function's initial state, find a collision between a single-block message and a message of 2^(k-1)+1 blocks. 
                  # DO NOT hash the entire long message each time. Choose 2^(k-1) dummy blocks, hash those, then focus on the last block. 
        # Step 1.2: Take the output state from the first step. Use this as your new initial state 
                  # and find another collision between a single-block message and a message of 2^(k-2)+1 blocks. 
        # Step 1.3: Repeat this process k total times. Your last collision should be between a single-block message and a message of 2^0+1 = 2 blocks. 
    # Step 2: Hash M and generate a map of intermediate hash states to the block indices that they correspond to
    # Step 3: Find a single-block "bridge" to intermediate state in map
    # Step 4: Generate a prefix of the right length such that len(prefix || bridge || M[i..]) = len(M)

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

def generate_messages(k):
    h = '\x00\x00'
    state_size = len(h)
    collisions = []

    while k > 0:
        lookup = {}
        prefix = '\x00' * AES.block_size * (2 ** (k - 1))
        pre_hash = merkle_damgard(prefix, h)

        for _ in range(2 ** (state_size * 8)):
            m = urandom(state_size)
            lookup[merkle_damgard(m, h)] = m

        m = urandom(state_size)
        hashed = merkle_damgard(m, pre_hash)
        while hashed not in lookup:
            m = urandom(state_size)
            hashed = merkle_damgard(m, pre_hash)

        collisions.append((prefix + m, lookup[hashed]))

        k -= 1
        h = hashed

    return collisions, hashed


def block_hash_map(M):
    block_to_index = {}
    h = '\x00\x00'
    M = pkcs7_padding(M)

    for i in range(len(M) / AES.block_size):
        start = i * AES.block_size
        end = start + AES.block_size
        block = M[start:end]

        hashed = merkle_damgard(block, h, nopadding=True)
        block_to_index[hashed] = i
        h = hashed

    return block_to_index


def generate_prefix(length, pairs):
    length *= AES.block_size
    prefix = ''

    for long, short in pairs:
        segment = long if length >= len(long) else short

        segment = pkcs7_padding(segment)
        prefix += segment
        length -= len(segment)

        if length == 0:
            return prefix


def long_message_attack():
    k = 16
    M = urandom(AES.block_size * 2 ** k)

    # Step 1: Generate an expandable message of length (k, k + 2^k - 1)
    collision_pairs, final_state = generate_messages(k)
    
    # Step 2: Hash M and generate a map of intermediate hash states to the block indices that they correspond to
    intermediate_hashes = block_hash_map(M)
    while final_state not in intermediate_hashes:
        collision_pairs, final_state = generate_messages(k)

    # Step 3: Find a single-block "bridge" to intermediate state in map
    bridge_index = intermediate_hashes[final_state] + 1
    bridge_offset = bridge_index * AES.block_size
    print 'Bridge block is at index {}'.format(bridge_index)

    # Step 4: Generate a prefix of the right length such that len(prefix || bridge || M[i..]) = len(M)
    prefix = generate_prefix(bridge_index, collision_pairs)
    assert len(prefix) == (bridge_index * AES.block_size)

    preimage = prefix + M[bridge_offset:]
    assert len(preimage) == len(M)
    print "Hash of preimage: " + merkle_damgard(preimage, '\x00\x00')
    print "Hash of M: " + merkle_damgard(M, '\x00\x00')
    assert merkle_damgard(preimage, '\x00\x00') == merkle_damgard(M, '\x00\x00')
    return 'Found a preimage for message M with length 2^{}'.format(k)


print long_message_attack()