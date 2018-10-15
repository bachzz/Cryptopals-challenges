import sys
import struct
from struct import pack, unpack
from binascii import unhexlify, hexlify
from random import randint

sys.path.insert(0, './lib')
from my_crypto_lib import *
from hashlib import sha256
		####### 	SHA-1		########

def left_rotate(value, shift):
    """Returns value left-rotated by shift bits. In other words, performs a circular shift to the left."""
    return ((value << shift) & 0xffffffff) | (value >> (32 - shift))


def sha1(message, ml=None, h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0):
    """Returns a string containing the SHA1 hash of the input message. 
    Implemented from: https://en.wikipedia.org/wiki/SHA-1
    """
    # Pre-processing:
    if ml is None:
        ml = len(message) * 8

    message += b'\x80'
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'

    message += struct.pack('>Q', ml)

    # Process the message in successive 512-bit chunks:
    for i in range(0, len(message), 64):

        # Break chunk into sixteen 32-bit big-endian integers w[i]
        w = [0] * 80
        for j in range(16):
            w[j] = struct.unpack('>I', message[i + j * 4:i + j * 4 + 4])[0]

        # Extend the sixteen 32-bit integers into eighty 32-bit integers:
        for j in range(16, 80):
            w[j] = left_rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)

        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # Main loop
        for j in range(80):
            if j <= 19:
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (d & (b | c))
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = left_rotate(a, 5) + f + e + k + w[j] & 0xffffffff
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        # Add this chunk's hash to result so far:
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    # Produce the final hash value (big-endian) as a 160 bit number, hex formatted:
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)


def sha1_mac(key, message):
    return sha1(key + message)


        #####     MD4      ######

class MD4:
    """Adapted from: https://github.com/FiloSottile/crypto.py/blob/master/3/md4.py"""
    buf = [0x00] * 64

    _F = lambda self, x, y, z: ((x & y) | (~x & z))
    _G = lambda self, x, y, z: ((x & y) | (x & z) | (y & z))
    _H = lambda self, x, y, z: (x ^ y ^ z)

    def __init__(self, message, ml=None, A=0x67452301, B=0xefcdab89, C=0x98badcfe, D=0x10325476):
        self.A, self.B, self.C, self.D = A, B, C, D

        if ml is None:
            ml = len(message) * 8

        length = pack('<Q', ml)

        while len(message) > 64:
            self._handle(message[:64])
            message = message[64:]

        message += b'\x80'
        message += bytes((56 - len(message) % 64) % 64)
        message += length

        # while len(message):
        #     #print len(message)
        #     if len(message) < 64:
        #       message += "\x00" * (64-len(message))
        #     self._handle(message[:64])
        #     message = message[64:]

    def _handle(self, chunk):
        #X = list(unpack('<' + 'I' * 16, chunk))
        X = list(unpack("<16I", chunk))
        A, B, C, D = self.A, self.B, self.C, self.D

        for i in range(16):
            k = i
            if i % 4 == 0:
                A = left_rotate((A + self._F(B, C, D) + X[k]) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = left_rotate((D + self._F(A, B, C) + X[k]) & 0xffffffff, 7)
            elif i % 4 == 2:
                C = left_rotate((C + self._F(D, A, B) + X[k]) & 0xffffffff, 11)
            elif i % 4 == 3:
                B = left_rotate((B + self._F(C, D, A) + X[k]) & 0xffffffff, 19)

        for i in range(16):
            k = (i // 4) + (i % 4) * 4
            if i % 4 == 0:
                A = left_rotate((A + self._G(B, C, D) + X[k] + 0x5a827999) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = left_rotate((D + self._G(A, B, C) + X[k] + 0x5a827999) & 0xffffffff, 5)
            elif i % 4 == 2:
                C = left_rotate((C + self._G(D, A, B) + X[k] + 0x5a827999) & 0xffffffff, 9)
            elif i % 4 == 3:
                B = left_rotate((B + self._G(C, D, A) + X[k] + 0x5a827999) & 0xffffffff, 13)

        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            k = order[i]
            if i % 4 == 0:
                A = left_rotate((A + self._H(B, C, D) + X[k] + 0x6ed9eba1) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = left_rotate((D + self._H(A, B, C) + X[k] + 0x6ed9eba1) & 0xffffffff, 9)
            elif i % 4 == 2:
                C = left_rotate((C + self._H(D, A, B) + X[k] + 0x6ed9eba1) & 0xffffffff, 11)
            elif i % 4 == 3:
                B = left_rotate((B + self._H(C, D, A) + X[k] + 0x6ed9eba1) & 0xffffffff, 15)

        self.A = (self.A + A) & 0xffffffff
        self.B = (self.B + B) & 0xffffffff
        self.C = (self.C + C) & 0xffffffff
        self.D = (self.D + D) & 0xffffffff

    def digest(self):
        return pack('<4I', self.A, self.B, self.C, self.D)

    def hex_digest(self):
        return hexlify(self.digest()).decode()

            ##### DIFFIE - HELMAN #####

def modexp ( g, u, p ):
   """computes s = (g ^ u) mod p
      args are base, exponent, modulus"""
   s = 1
   while u != 0:
      if u & 1:
         s = (s * g)%p
      u >>= 1
      g = (g * g)%p;
   return s


class diffie_helman():
    def __init__(self):
        self.p = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
            "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
            "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
            "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
            "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
            "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
            "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
            "fffffffffffff",16)
        self.g = 2
        self.u = randint(0, self.p-1)
        self._public_key = 0
    def public_key(self, g = 0, p = 0):
        if g == 0 and p == 0:
            g = self.g
            p = self.p
        #self.u = randint(0, p-1)
        self._public_key = modexp(g, self.u, p)
        return self._public_key
    def secret_key(self, _S):
        return modexp(_S, self.u, self.p)

        
        ### HMAC - SHA256

# def hmac_sha256(key, message):
#     """Returns the HMAC-SHA256 for the given key and message. Written following Wikipedia pseudo-code."""

#     if len(key) > 64:
#         key = sha256(key).digest()
#     if len(key) < 64:
#         key += "\x00" * (64 - len(key))

#     o_key_pad = xor("\x5c" * 64, key)
#     i_key_pad = xor("\x36" * 64, key)
#     #o_key_pad = o_key_pad.encode('utf-8')
#     #i_key_pad = i_key_pad.encode('utf-8')
#     # #print ascii_to_hex(o_key_pad)
#     # #print ascii_to_hex(i_key_pad)
#     st0_1 = unicode(i_key_pad, errors='ignore')
#     st0 = st0_1 + message
#     st = unicode(sha256(st0).digest(), errors='ignore')
#     st_1 = unicode(o_key_pad, errors='ignore')
#     st2 = st_1 + st
#     #st2 = unicode(st2,errors='ignore')
#     #return sha256(o_key_pad + sha256(i_key_pad + message).digest()).hexdigest()
#     return sha256(st2).hexdigest()

def hmac_sha256(key, message):
    """Returns the HMAC-SHA256 for the given key and message. Written following Wikipedia pseudo-code."""

    if len(key) > 64:
        key = sha256(key).digest()
    if len(key) < 64:
        key = b'\x00' * (64 - len(key))

    o_key_pad = xor(b'\x5c' * 64, key)
    i_key_pad = xor(b'\x36' * 64, key)

    return sha256(o_key_pad + sha256(i_key_pad + message).digest()).hexdigest()

# def hmac_sha256(key, message): 
#     blockSize = 64  # the block size of the underlying hash function (e.g. 64 bytes for SHA-1)
#     outputSize = 20  # the output size of the underlying hash function (e.g. 20 bytes for SHA-1)

#     # Keys longer than blockSize are shortened by hashing them
#     if len(key) > blockSize:
#         key = sha1(key)
#     # Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
#     if len(key) < blockSize:
#         key = "\x00" * (blockSize - len(key))

#     o_key_pad = xor(key, "\x5c" * blockSize)     # Outer padded key
#     i_key_pad = xor(key, "\x36" * blockSize)    # Inner padded key

#     return sha256(o_key_pad + sha256(i_key_pad + message).digest()).hexdigest() # return hex