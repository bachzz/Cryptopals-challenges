### EXPLAIN! EXPLAIN! EXPLAIN!

## WHAT WE HAVE?
    # A ciphertext
    # A paddding oracle (a service that receives ciphertext -> decrypts it -> check valid PKCS7 padding -> return True | False)

## GOAL?
    # Decrypt ciphertext by calling padding oracle repeatedly (brute-force)

## How?
    # Suppose we have 2 ciphertext blocks: C = C1 || C2, and plaintext of C2 is P2
    # Let the last byte in ciphertext block 1 be C1_15, last one in decrypted block 2 be D1_15, last one in plaintext block 2 be P2_15
    # Goal: guess P2_15 correctly
    # How?
        # Change C1_15 = C1_15 XOR guess XOR '0x01' -> We have new C' 
        # Brute-force guess ( 0 <= guess <= 256), for each guess, padding_oracle(C') to get 
        #   P2_15' = C1_15' XOR D1_15 = C1_15 XOR guess XOR '0x01' XOR D1_15 = P2_15 XOR guess XOR '0x01'
        # If guess == P2_15 => Save guess
    # Repeat with second to last byte, third to last byte, ... with padding byte "0x02","0x03",...
    # => Decrypted block C2
    # Repeat the same process to decrypt block C3 by modifying ciphertext block C2, C4 by C3, C5 by C4, ...
    # NOTE: Decrypt block C1 why modifying ciphertext IV


import sys
sys.path.insert(0, './lib')
from my_crypto_lib import *

from helpers import *
import random
from base64 import b64decode

stringpool = [
 'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
 'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
 'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
 'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
 'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
 'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
 'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
 'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
 'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
]

key = generateRandomData()


def encrypt(plaintext):
    iv = generateRandomData()
    plaintext = pkcs7Padding(plaintext)
    print ' Original:', bytesToText(removePkcs7Padding(plaintext))
    cipher = encryptCBC(plaintext, key, iv)
    return iv + cipher


def paddingOracle(cipherAndIV):
    cipher = cipherAndIV[16:]
    iv = cipherAndIV[:16]
    plaintext = decryptCBC(cipher, key, iv)
    #plaintext=aes_cbc_dec(128,cipher,key,iv)
    #print "".join(plaintext)
    try:
        return checkPkcs7Padding(plaintext)
    except ValueError:
        return False


def recoverPlaintext(cipherAndIV):
    recovered = []
    recoveredBlock = []

    # split cipherAndIV into 16-byte blocks
    cipherblocks = [chunk for chunk in chunks(cipherAndIV)]

    for offset in xrange(len(cipherblocks) - 1):
        # the original ciphertext is needed for the xor'ing
        xorCipherblock = cipherblocks[offset]

        # the leading 0 will be used to find valid padding, the cipherblock
        # is the part that will be recovered
        workingBlock = [0] * 16 + cipherblocks[offset + 1]

        # pos is the position of the byte we are trying to find
        # using negative index into the byte lists
        for pos in [x for x in reversed(range(-16, 0))]:  # [-1, -2, ..., -16]
            # how many bytes do we have? Need this to construct valid padding
            recoveredBytesCount = len(recoveredBlock)


            if recoveredBytesCount > 0:
                # make sure the ciphertext has valid padding
                for i in xrange(recoveredBytesCount):
                    # if we have e.g. two bytes recovered, we want the padding
                    # to be 0x03, we need to modify the ciphertext accordingly

                    # paddingValue ^ origC ^ recoveredP
                    workingBlock[-17 - i] = \
                        (recoveredBytesCount + 1) ^ \
                        xorCipherblock[-1 - i] ^ recoveredBlock[i]

            # now start guessing bytes
            for byte in xrange(256):
                workingBlock[pos - 16] = byte  # set the byte
                result = paddingOracle(workingBlock[:])  # check the oracle
                if result:  # if the padding is valid...
                    # calculate the actual plaintext
                    # paddingValue ^ guessed byte ^ original ciphertext byte
                    recoveredBlock.append((recoveredBytesCount + 1) ^ byte ^
                                          xorCipherblock[pos])
                    break
        # the recovered block bytes are reversed b/c we started w/ the last one
        recovered.extend([b for b in reversed(recoveredBlock)])
        recoveredBlock = []
    return recovered


def main():
    # choose random plain text
    plain = b64decode(random.choice(stringpool))
    # encrypt the plaintext, prepend the IV
    cipherAndIV = encrypt(textToByteList(plain))

    # run the intercepted ciphertext against the padding oracle
    plain = recoverPlaintext(cipherAndIV)
    print 'Recovered:', bytesToText(removePkcs7Padding(plain))


if __name__ == '__main__':
    main()