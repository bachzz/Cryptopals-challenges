### EXPLAIN!!!

## GOOD reference: http://www.isg.rhul.ac.uk/tls/RC4biases.pdf#figure.2

## WHAT WE HAVE?
    # An oracle:
    #       - Receive request (P)
    #       - Append request (P) with "secret cookie"
    #       - Return ciphertext P + cookie encrypted with RC4 using different keys every request 

## GOAL: Decode this secret cookie: "QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F" by spawning arbitrary requests
##       and analyse the ciphertext

## Single-byte biases theorems:
    # 1. The probability that Z2, the second byte of keystream output by RC4, is equal to 0x00 is approximately 1/128
    # 2. For 3 <= r <= 255, the probability that Zr, the r-th byte of keystream output by RC4, is equal to 0x00 is:
    #               Pr(Zr = 0x00) = 1/256 + Cr/256^2
    # => Since Cr = Pr XOR Zr, Zr -> 0x00 => Cr -> Pr (corresonding ciphertext byte has bias toward plaintext byte Pr)
                        #### ** IMPORTANT!! ** ####
    # Thus, obtaining many ciphertext samples Cr for a fixed plaintext Pr allows interference of Pr by a majority vote:
    # => Pr is equal to the value of Cr that occurs most often

## Single-byte bias attack algorithm:
##      Check Algorithm 4 here: http://www.isg.rhul.ac.uk/tls/RC4biases.pdf

## MAIN STEPS:
    # Step 1: Gain exhaustive knowledge of the keystream biases.
    # Step 2: Encrypt the unknown plaintext 2^30+ times under different keys.
    # Step 3: Compare the ciphertext biases against the keystream biases.

## NOTE: control the position of the cookie by requesting "/", "/A", "/AA", and so on 
##       (to guess next byte in plaintext)

import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *

from base64 import b64decode
from operator import itemgetter
from os import urandom

from Crypto.Cipher import ARC4


def _rc4_encryption_oracle(request):
    cookie = b64decode('QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F')
    fresh_key = urandom(16)

    cipher = ARC4.new(fresh_key)
    return cipher.encrypt(request + cookie)


def rc4_single_byte_bias_attack():
    cookie_len = len(_rc4_encryption_oracle(''))
    z16, z32 = 15, 31
    z16_bias, z32_bias = 0xf0, 0xe0
    plaintext = ['?'] * cookie_len

    for i in range((cookie_len / 2) + 1):
        offset = z16 - i
        request = 'A' * offset
        z16_map, z32_map = {}, {}
        check_z32 = z32 < (len(request) + cookie_len)

        for j in xrange(2**24):
            result = _rc4_encryption_oracle(request)

            try:
                z16_map[result[z16]] += 1
            except KeyError:
                z16_map[result[z16]] = 1

            if check_z32:
                try:
                    z32_map[result[z32]] += 1
                except KeyError:
                    z32_map[result[z32]] = 1

        z16_char = max(z16_map.items(), key=itemgetter(1))[0]
        plaintext[z16 - offset] = chr(ord(z16_char) ^ z16_bias)

        if check_z32:
            z32_char = max(z32_map.items(), key=itemgetter(1))[0]
            plaintext[z32 - offset] = chr(ord(z32_char) ^ z32_bias)

        print ''.join(plaintext)

    return 'Recovered message "{}"'.format(''.join(plaintext))

print rc4_single_byte_bias_attack()